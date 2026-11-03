// Guardian service worker: guards every top-level navigation.
//   whitelisted site        -> nothing happens, the page loads normally
//   anything else           -> the tab is sent to check.html, which asks us for a verdict
//                              (PhishTank / Google Safe Browsing / VirusTotal) before the page opens
import { PublicSuffixList } from "./lib/psl.js";
import { Whitelist, isLocal, normalize } from "./lib/whitelist.js";
import { Reputation, PhishTank } from "./lib/reputation.js";

const PROCEED_TTL = 3600e3;  // "Continue anyway" lasts one hour for that site
const FEED_URL = "https://data.phishtank.com/data/online-valid.csv";
const FEED_REFRESH_MIN = 180;
const RETRY_AFTER_MIN = 30;  // minimum gap between feed download attempts, even after a failure

// ---- storage helpers -----------------------------------------------------------------------
const local = chrome.storage.local;
const session = chrome.storage.session;
const kv = {
  async get(k) { return (await session.get(k))[k]; },
  async set(k, v) { await session.set({ [k]: v }); },
};
const getKey = async (name) => ((await local.get("keys")).keys || {})[name] || "";

// ---- whitelist (loaded once per service-worker lifetime) -----------------------------------
let wlPromise = null;
function getWhitelist() {
  wlPromise ??= (async () => {
    const [psl, gz, cats, categories] = await Promise.all([
      fetch(chrome.runtime.getURL("data/psl.dat")).then((r) => r.text()),
      fetch(chrome.runtime.getURL("data/domains.txt.gz")).then((r) => r.arrayBuffer()),
      fetch(chrome.runtime.getURL("data/cats.bin")).then((r) => r.arrayBuffer()),
      fetch(chrome.runtime.getURL("data/categories.json")).then((r) => r.json()),
    ]);
    return Whitelist.fromGzip(gz, new Uint8Array(cats), categories, new PublicSuffixList(psl));
  })();
  return wlPromise;
}

// ---- reputation ----------------------------------------------------------------------------
const rep = new Reputation({ fetch: (...a) => fetch(...a), kv, getKey });
let feedReady = null;
function loadFeed() {
  feedReady ??= (async () => {
    const { ptKeys } = await local.get("ptKeys");
    rep.phishtank.loadKeys(ptKeys || "");
    const { ptTime } = await local.get("ptTime");
    if (!ptKeys || Date.now() - (ptTime || 0) > FEED_REFRESH_MIN * 60e3) updateFeed();
  })();
  return feedReady;
}

async function updateFeed() {
  // PhishTank rate-limits downloads (HTTP 429): after any attempt, wait before trying again.
  const { ptTry = 0 } = await local.get("ptTry");
  if (Date.now() - ptTry < RETRY_AFTER_MIN * 60e3) return;
  await local.set({ ptTry: Date.now() });
  try {
    const r = await fetch(FEED_URL);
    if (!r.ok) throw new Error("HTTP " + r.status);
    const keys = PhishTank.parseFeed(await r.text());
    await local.set({ ptKeys: keys, ptTime: Date.now() });
    rep.phishtank.loadKeys(keys);
  } catch (e) {
    console.warn("PhishTank feed update failed:", e);
  }
}

// ---- on / off ------------------------------------------------------------------------------
async function isEnabled() {
  return (await local.get("enabled")).enabled !== false; // on by default
}

async function showBadge() {
  const on = await isEnabled();
  await chrome.action.setBadgeText({ text: on ? "" : "OFF" });
  await chrome.action.setBadgeBackgroundColor({ color: "#6b7280" });
  await chrome.action.setTitle({ title: on ? "Guardian: protection ON" : "Guardian: protection OFF" });
}

chrome.storage.onChanged.addListener((ch, area) => {
  if (area === "local" && ch.enabled) showBadge();
});

// ---- "Continue anyway" ---------------------------------------------------------------------
async function isAllowed(host) {
  const allowed = (await kv.get("allowed")) || {};
  return (allowed[host] || 0) > Date.now();
}

async function allowHost(host) {
  const allowed = (await kv.get("allowed")) || {};
  allowed[host] = Date.now() + PROCEED_TTL;
  await kv.set("allowed", allowed);
}

// ---- stats ---------------------------------------------------------------------------------
async function bump(name) {
  const { stats = {} } = await local.get("stats");
  stats[name] = (stats[name] || 0) + 1;
  await local.set({ stats });
}

// ---- navigation guard ----------------------------------------------------------------------
async function guard(tabId, url) {
  if (!(await isEnabled())) return;
  let host;
  try { host = normalize(new URL(url).hostname); } catch { return; }
  if (!host || isLocal(host) || (await isAllowed(host))) return;
  if ((await getWhitelist()).lookup(host)) return;
  loadFeed();
  const page = chrome.runtime.getURL("check.html") + "?u=" + encodeURIComponent(url);
  try { await chrome.tabs.update(tabId, { url: page }); } catch { /* tab closed */ }
}

const HTTP = { url: [{ schemes: ["http", "https"] }] };

chrome.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId === 0 && d.tabId >= 0) guard(d.tabId, d.url);
}, HTTP);

// Catches pages reached by a redirect from an allowed site.
chrome.webNavigation.onCommitted.addListener((d) => {
  const q = d.transitionQualifiers || [];
  if (d.frameId === 0 && d.tabId >= 0 && (q.includes("server_redirect") || q.includes("client_redirect"))) {
    guard(d.tabId, d.url);
  }
}, HTTP);

// ---- messages from check.html --------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return;
  (async () => {
    if (msg.type === "check") {
      await loadFeed();
      let host = "";
      try { host = normalize(new URL(msg.url).hostname); } catch { /* bad URL */ }
      if (!host || (await isAllowed(host)) || (await getWhitelist()).lookup(host)) {
        return reply({ action: "allow" });
      }
      const r = await rep.check(msg.url);
      bump(r.found ? "blocked" : "warned");
      reply({ action: r.found ? "block" : "warn", risk: r.risk, sources: r.sources,
              checked: r.checked, unavailable: r.unavailable });
    } else if (msg.type === "proceed") {
      await allowHost(normalize(new URL(msg.url).hostname));
      reply({ ok: true });
    }
  })().catch((e) => reply({ action: "error", error: String(e) }));
  return true; // async reply
});

// ---- lifecycle -----------------------------------------------------------------------------
chrome.runtime.onInstalled.addListener((d) => {
  chrome.alarms.create("feed", { periodInMinutes: FEED_REFRESH_MIN });
  showBadge();
  getWhitelist();
  loadFeed();
  if (d.reason === "install") chrome.runtime.openOptionsPage();
});
chrome.runtime.onStartup.addListener(showBadge);
chrome.alarms.onAlarm.addListener((a) => { if (a.name === "feed") updateFeed(); });
