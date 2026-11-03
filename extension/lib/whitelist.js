// Layer 1: whitelist of ~1,000,000 trusted domains, kept as one sorted byte buffer and searched
// with binary search (about 20 MB of memory, no per-domain JS strings).

export function normalize(host) {
  return host.trim().toLowerCase().replace(/\.$/, "");
}

export function isIp(host) {
  const h = host.replace(/^\[|\]$/g, "");
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(":");
}

// Local / private addresses are never checked.
export function isLocal(host) {
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return true;
  const h = host.replace(/^\[|\]$/g, "");
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (m) {
    const a = +m[1], b = +m[2];
    return a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || a === 0;
  }
  if (h.includes(":")) {
    return h === "::1" || h === "::" || /^f[cd]/i.test(h) || /^fe[89ab]/i.test(h);
  }
  return false;
}

export class Whitelist {
  constructor(bytes, cats, categories, psl) {
    this.bytes = bytes;
    this.cats = cats;
    this.categories = categories;
    this.psl = psl;
    let n = 1;
    for (let i = 0; i < bytes.length; i++) if (bytes[i] === 10) n++;
    this.count = n;
    this.starts = new Uint32Array(n + 1);
    let k = 1;
    for (let i = 0; i < bytes.length; i++) if (bytes[i] === 10) this.starts[k++] = i + 1;
    this.starts[n] = bytes.length + 1;
    this.enc = new TextEncoder();
  }

  static async fromGzip(gz, cats, categories, psl) {
    const stream = new Blob([gz]).stream().pipeThrough(new DecompressionStream("gzip"));
    const bytes = new Uint8Array(await new Response(stream).arrayBuffer());
    return new Whitelist(bytes, cats, categories, psl);
  }

  // Index of `domain` in the sorted list, or -1.
  find(domain) {
    const q = this.enc.encode(domain);
    let lo = 0, hi = this.count - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const s = this.starts[mid], len = this.starts[mid + 1] - s - 1;
      const c = this._cmp(q, s, len);
      if (c === 0) return mid;
      if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return -1;
  }

  _cmp(q, s, len) {
    const m = Math.min(q.length, len);
    for (let i = 0; i < m; i++) {
      const d = q[i] - this.bytes[s + i];
      if (d) return d;
    }
    return q.length - len;
  }

  // The host, then each parent up to the registrable domain (inclusive).
  candidates(host) {
    if (isIp(host)) return [];
    const base = this.psl.registrable(host);
    if (!base) return [host];
    const labels = host.split("."), out = [];
    for (let i = 0; i < labels.length; i++) {
      const cand = labels.slice(i).join(".");
      out.push(cand);
      if (cand === base) break;
    }
    return out;
  }

  // -> { category, matched } or null
  lookup(host) {
    for (const cand of this.candidates(normalize(host))) {
      const i = this.find(cand);
      if (i >= 0) return { category: this.categories[this.cats[i]], matched: cand };
    }
    return null;
  }
}
