// Run:  node --test tests/extension.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { PublicSuffixList } from "../extension/lib/psl.js";
import { Whitelist, isLocal } from "../extension/lib/whitelist.js";
import { Reputation, PhishTank, riskOf, urlKey } from "../extension/lib/reputation.js";

const D = new URL("../extension/data/", import.meta.url);
const psl = new PublicSuffixList(readFileSync(new URL("psl.dat", D), "utf8"));
const wl = await Whitelist.fromGzip(
  readFileSync(new URL("domains.txt.gz", D)),
  new Uint8Array(readFileSync(new URL("cats.bin", D))),
  JSON.parse(readFileSync(new URL("categories.json", D), "utf8")), psl);

test("public suffix list", () => {
  assert.equal(psl.registrable("mail.google.com"), "google.com");
  assert.equal(psl.registrable("a.b.example.co.uk"), "example.co.uk");
  assert.equal(psl.registrable("user.github.io"), "user.github.io"); // private suffix: its own site
  assert.equal(psl.registrable("github.io"), null);
  assert.equal(psl.registrable("rru.ac.in"), "rru.ac.in");
  assert.equal(psl.registrable("www.rru.ac.in"), "rru.ac.in");
  assert.equal(psl.registrable("x.notarealtld"), null);
  assert.equal(psl.registrable("a.b.ck"), "a.b.ck"); // wildcard *.ck
  assert.equal(psl.registrable("www.ck"), "www.ck");   // exception !www.ck
});

test("whitelist: 1,000,000 domains", () => {
  assert.equal(wl.count, 1_000_000);
});

test("whitelist lookups", () => {
  assert.deepEqual(wl.lookup("google.com"), { category: "Search & Portals", matched: "google.com" });
  assert.equal(wl.lookup("www.google.com").matched, "google.com");
  assert.equal(wl.lookup("mail.google.com").matched, "google.com");
  assert.equal(wl.lookup("rru.ac.in").category, "Education & Research");
  assert.equal(wl.lookup("WWW.RRU.AC.IN.").matched, "rru.ac.in");
  assert.equal(wl.lookup("g00gle-login-secure.xyz"), null);
  assert.equal(wl.lookup("google.com.evil.example"), null);
  assert.equal(wl.lookup("someuser.github.io"), null);
  assert.equal(wl.lookup("someuser.blogspot.com"), null);
  assert.equal(wl.lookup("8.8.8.8"), null);
  assert.equal(wl.lookup("br-icloud.com.br"), null);
});

test("whitelist: every sampled domain is found with its own category", () => {
  let checked = 0;
  for (let i = 0; i < wl.count; i += 997) {
    const s = wl.starts[i], e = wl.starts[i + 1] - 1;
    const d = new TextDecoder().decode(wl.bytes.subarray(s, e));
    assert.equal(wl.find(d), i, d);
    checked++;
  }
  assert.ok(checked > 1000);
});

test("local addresses", () => {
  for (const h of ["localhost", "a.localhost", "printer.local", "127.0.0.1", "10.1.2.3", "192.168.0.9",
                   "172.20.1.1", "169.254.1.1", "[::1]", "fe80::1", "fd12::1"]) assert.ok(isLocal(h), h);
  for (const h of ["8.8.8.8", "172.32.0.1", "example.com", "2001:db8::1"]) assert.ok(!isLocal(h), h);
});

// ---- reputation ----------------------------------------------------------------------------
function mem() {
  const m = new Map();
  return { get: async (k) => m.get(k), set: async (k, v) => void m.set(k, v) };
}
const KEYS = { safebrowsing: "g", virustotal: "v" };
function make({ gsb = false, vt = 0, keys = KEYS, delay = {}, vtStatus = 200 } = {}) {
  const calls = [];
  const sleep = (ms, signal) => new Promise((res, rej) => {
    const t = setTimeout(res, ms);
    signal?.addEventListener("abort", () => { clearTimeout(t); rej(new Error("aborted")); });
  });
  const fetch = async (url, o) => {
    calls.push(url);
    if (url.includes("googleapis")) {
      await sleep(delay.gsb || 0, o.signal);
      return { ok: true, status: 200, json: async () => (gsb ? { matches: [{}] } : {}) };
    }
    await sleep(delay.vt || 0, o.signal);
    return { ok: vtStatus === 200, status: vtStatus,
             json: async () => ({ data: { attributes: { last_analysis_stats: { malicious: vt } } } }) };
  };
  const rep = new Reputation({ fetch, kv: mem(), getKey: async (n) => keys[n] || "", timeoutMs: 300 });
  rep.phishtank.loadKeys("");
  rep.phishtank.loaded = true;
  return { rep, calls };
}

test("risk: 33 / 66 / 100", () => {
  assert.deepEqual([0, 1, 2, 3].map((n) => riskOf(new Array(n).fill("x"))), [0, 33, 66, 100]);
});

test("each combination of sources gives the right risk", async () => {
  for (const [pt, gsb, vt, risk] of [[1, 0, 0, 33], [0, 1, 0, 33], [0, 0, 2, 33], [1, 1, 0, 66],
                                     [0, 1, 3, 66], [1, 0, 2, 66], [1, 1, 5, 100], [0, 0, 0, 0]]) {
    const { rep } = make({ gsb: !!gsb, vt });
    rep.phishtank.loadKeys(pt ? "bad.example/x" : "other.example");
    const r = await rep.check("http://bad.example/x");
    assert.equal(r.risk, risk, JSON.stringify([pt, gsb, vt]));
    assert.equal(r.found, risk > 0);
    assert.deepEqual(r.unavailable, []);
  }
});

test("VirusTotal needs 2 engines by default; 404 means never seen", async () => {
  assert.equal((await make({ vt: 1 }).rep.check("http://a.example/")).found, false);
  assert.equal((await make({ vt: 2 }).rep.check("http://a.example/")).found, true);
  const r = await make({ vtStatus: 404 }).rep.check("http://a.example/");
  assert.equal(r.found, false);
  assert.deepEqual(r.unavailable, []);
});

test("missing keys are reported as unavailable, not as 'clean'", async () => {
  const r = await make({ keys: {} }).rep.check("http://a.example/");
  assert.deepEqual(r.unavailable.sort(), ["Google Safe Browsing", "VirusTotal"]);
  assert.deepEqual(r.checked, ["PhishTank"]);
});

test("a slow source is cut off by the time limit and reported", async () => {
  const { rep } = make({ gsb: true, delay: { vt: 5000 } });
  const t = Date.now();
  const r = await rep.check("http://slow.example/");
  assert.ok(Date.now() - t < 1500);
  assert.equal(r.found, true);
  assert.deepEqual(r.sources, ["Google Safe Browsing"]);
  assert.deepEqual(r.unavailable, ["VirusTotal"]);
});

test("results are cached; VirusTotal limited to 4 lookups a minute", async () => {
  const { rep, calls } = make();
  await rep.check("http://a.example/");
  await rep.check("http://a.example/");
  assert.equal(calls.length, 2); // one GSB + one VT, second check came from the cache
  const r = [];
  for (let i = 0; i < 6; i++) r.push(await rep.check(`http://site${i}.example/`));
  assert.ok(r.slice(3).every((x) => x.unavailable.includes("VirusTotal")), "5th and later VT lookups are refused");
});

test("PhishTank feed parsing", () => {
  const csv = 'phish_id,url,phish_detail_url\n1,"http://bad.example/a,b?x=1",d\n2,http://worse.example/,d\n';
  const pt = new PhishTank();
  pt.loadKeys(PhishTank.parseFeed(csv));
  assert.ok(pt.contains("http://bad.example/a,b?x=1"));
  assert.ok(pt.contains("http://worse.example"));
  assert.ok(pt.contains("https://WORSE.example/"));
  assert.ok(!pt.contains("http://bad.example/other"));
  assert.equal(urlKey("http://a.com"), "a.com");
});

const feed = "C:/Users/Sukriti/AppData/Local/Temp/pt_sample.csv";
test("real PhishTank feed parses to the same count as the Python version", { skip: !existsSync(feed) }, () => {
  const keys = PhishTank.parseFeed(readFileSync(feed, "utf8")).split("\n");
  assert.ok(keys.length > 10_000, String(keys.length));
});
