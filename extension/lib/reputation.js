// Layer 2: is this URL a known threat? PhishTank (local copy of its feed), Google Safe Browsing,
// VirusTotal. A port of guardian/reputation.py, with the same rules:
//   - any source flags it -> malicious, risk 33% / 66% / 100% for 1 / 2 / 3 sources
//   - GSB and VirusTotal are asked in parallel under a hard time limit; one that cannot answer
//     (no key, timeout, rate limit, error) is reported as "unavailable" and counts as "not flagged"
//   - VirusTotal counts as "flagged" when at least `vtMin` engines call the URL malicious

export const GSB = "Google Safe Browsing";
export const VT = "VirusTotal";
export const PT = "PhishTank";

export const RISK = [0, 33, 66, 100];
const FOUND_TTL = 6 * 3600e3, CLEAN_TTL = 1800e3, PARTIAL_TTL = 60e3;

export class Unavailable extends Error {}

export function riskOf(sources) {
  return RISK[Math.min(sources.length, 3)];
}

// ---- PhishTank feed ------------------------------------------------------------------------
export function urlKey(url) {
  let u;
  try { u = new URL(url.trim()); } catch { return ""; }
  const q = u.search ? "?" + u.search.slice(1) : "";
  return (u.hostname.toLowerCase() + (u.pathname || "/") + q).replace(/\/+$/, "");
}

// Minimal CSV reader (handles quoted fields with commas, quotes and newlines).
export function* csvRows(text) {
  let row = [], field = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false; }
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field); field = "";
      yield row; row = [];
    } else field += c;
  }
  if (field || row.length) { row.push(field); yield row; }
}

export class PhishTank {
  constructor() { this.keys = new Set(); this.loaded = false; }

  // From the downloaded CSV: returns the keys as a newline-joined string (what we store).
  static parseFeed(text) {
    const keys = new Set();
    let col = 1, first = true;
    for (const row of csvRows(text)) {
      if (first) { first = false; const i = row.indexOf("url"); if (i >= 0) col = i; continue; }
      if (row.length > col) { const k = urlKey(row[col]); if (k) keys.add(k); }
    }
    return [...keys].join("\n");
  }

  loadKeys(joined) {
    this.keys = new Set(joined ? joined.split("\n") : []);
    this.loaded = this.keys.size > 0;
  }

  contains(url) {
    const k = urlKey(url);
    return !!k && (this.keys.has(k) || this.keys.has(k.split("?")[0]));
  }
}

// ---- Checker -------------------------------------------------------------------------------
// deps: { fetch, kv: {get(key), set(key, value)}, getKey(name), now(), timeoutMs, vtMin }
export class Reputation {
  constructor(deps) {
    this.d = { timeoutMs: 1500, vtMin: 2, now: () => Date.now(), ...deps };
    this.phishtank = new PhishTank();
    this.cache = null; // url -> { exp, result }, persisted in kv
  }

  async _loadCache() {
    if (this.cache) return;
    this.cache = new Map(Object.entries((await this.d.kv.get("repCache")) || {}));
  }

  async _saveCache() {
    const now = this.d.now();
    for (const [k, v] of this.cache) if (v.exp < now) this.cache.delete(k);
    while (this.cache.size > 300) this.cache.delete(this.cache.keys().next().value);
    await this.d.kv.set("repCache", Object.fromEntries(this.cache));
  }

  async _timed(fn) {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.d.timeoutMs);
    try { return await fn(ctl.signal); } finally { clearTimeout(t); }
  }

  async _gsb(url, signal) {
    const key = await this.d.getKey("safebrowsing");
    if (!key) throw new Unavailable("no key");
    let r;
    try {
      r = await this.d.fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + encodeURIComponent(key), {
        method: "POST", signal, headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "guardian", clientVersion: "0.1" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url }],
          },
        }),
      });
    } catch (e) { throw new Unavailable(String(e)); }
    if (!r.ok) throw new Unavailable("HTTP " + r.status);
    const out = await r.json();
    return !!(out.matches && out.matches.length);
  }

  // Free VirusTotal keys allow 4 lookups per minute; don't burn requests we know will fail.
  async _vtAllowed() {
    const now = this.d.now();
    const calls = ((await this.d.kv.get("vtCalls")) || []).filter((t) => now - t < 60e3);
    if (calls.length >= 4) { await this.d.kv.set("vtCalls", calls); return false; }
    calls.push(now);
    await this.d.kv.set("vtCalls", calls);
    return true;
  }

  async _vt(url, signal) {
    const key = await this.d.getKey("virustotal");
    if (!key) throw new Unavailable("no key");
    if (!(await this._vtAllowed())) throw new Unavailable("rate limit");
    const bytes = new TextEncoder().encode(url);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    const uid = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    let r;
    try {
      r = await this.d.fetch("https://www.virustotal.com/api/v3/urls/" + uid, { signal, headers: { "x-apikey": key } });
    } catch (e) { throw new Unavailable(String(e)); }
    if (r.status === 404) return false; // VirusTotal has never seen this URL
    if (!r.ok) throw new Unavailable("HTTP " + r.status);
    const data = await r.json();
    return (data.data.attributes.last_analysis_stats.malicious || 0) >= this.d.vtMin;
  }

  // -> { found, sources, checked, unavailable, risk }
  async check(url) {
    await this._loadCache();
    const now = this.d.now();
    const hit = this.cache.get(url);
    if (hit && hit.exp > now) return hit.result;

    const r = { found: false, sources: [], checked: [], unavailable: [] };
    if (this.phishtank.loaded) {
      r.checked.push(PT);
      if (this.phishtank.contains(url)) { r.found = true; r.sources.push(PT); }
    } else r.unavailable.push(PT);

    const asks = [[GSB, (s) => this._gsb(url, s)], [VT, (s) => this._vt(url, s)]];
    const settled = await Promise.allSettled(asks.map(([, f]) => this._timed(f)));
    settled.forEach((s, i) => {
      const name = asks[i][0];
      if (s.status === "fulfilled") {
        r.checked.push(name);
        if (s.value) { r.found = true; r.sources.push(name); }
      } else r.unavailable.push(name);
    });

    r.risk = riskOf(r.sources);
    const ttl = r.found ? FOUND_TTL : r.unavailable.length ? PARTIAL_TTL : CLEAN_TTL;
    this.cache.set(url, { exp: now + ttl, result: r });
    await this._saveCache();
    return r;
  }
}
