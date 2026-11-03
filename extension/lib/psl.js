// Public Suffix List: find the registrable domain of a host ("mail.google.com" -> "google.com").
// Private suffixes (github.io, blogspot.com ...) are included, so `user.github.io` is its own site.

export class PublicSuffixList {
  constructor(text) {
    this.rules = new Set();
    this.wild = new Set(); // "*.ck" is stored as "ck"
    this.exc = new Set();  // "!www.ck" is stored as "www.ck"
    for (const raw of text.split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("//")) continue;
      if (line.startsWith("!")) this.exc.add(line.slice(1));
      else if (line.startsWith("*.")) this.wild.add(line.slice(2));
      else this.rules.add(line);
    }
  }

  // Number of labels in the public suffix of `labels`, or 0 if no rule matches.
  suffixLength(labels) {
    const n = labels.length;
    let best = 0;
    for (let k = 1; k <= n; k++) {
      const suffix = labels.slice(n - k).join(".");
      if (this.exc.has(suffix)) return k - 1;
      if (this.rules.has(suffix)) best = Math.max(best, k);
      if (k >= 2 && this.wild.has(labels.slice(n - k + 1).join("."))) best = Math.max(best, k);
    }
    return best;
  }

  // "mail.google.com" -> "google.com"; null if the host is a public suffix itself or unknown TLD.
  registrable(host) {
    const labels = host.split(".");
    const s = this.suffixLength(labels);
    if (s === 0 || labels.length <= s) return null;
    return labels.slice(labels.length - s - 1).join(".");
  }
}
