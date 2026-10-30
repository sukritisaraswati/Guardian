"""Layer 1: whitelist lookup, backed by SQLite (domain -> category)."""
import csv
import gzip
import ipaddress
import sqlite3
from functools import lru_cache

import tldextract

from . import config

# Offline: use the bundled public-suffix snapshot. Private suffixes are included, so
# github.io, blogspot.com, herokuapp.com ... are treated as suffixes and `user.github.io`
# is its own site (whitelisting github.io does not whitelist every user page).
_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def ensure_db(force=False):
    """Build the SQLite database from the shipped CSV (first run, or if the CSV is newer)."""
    config.HOME.mkdir(parents=True, exist_ok=True)
    db = config.DB_FILE
    if db.exists() and not force and db.stat().st_mtime >= config.DATA_CSV.stat().st_mtime:
        return False
    tmp = db.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    con = sqlite3.connect(tmp)
    con.execute("CREATE TABLE w (domain TEXT PRIMARY KEY, category TEXT) WITHOUT ROWID")
    with gzip.open(config.DATA_CSV, "rt", encoding="utf-8", newline="") as f:
        rd = csv.reader(f)
        next(rd)
        con.executemany("INSERT OR IGNORE INTO w VALUES (?,?)", rd)
    con.commit()
    con.close()
    tmp.replace(db)
    return True


def normalize(host):
    return host.strip().lower().rstrip(".")


def _is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_local(host):
    if host == "localhost" or host.endswith((".localhost", ".local")):
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


class Whitelist:
    def __init__(self, path=None):
        self.con = sqlite3.connect(str(path or config.DB_FILE), check_same_thread=False)
        self.lookup = lru_cache(maxsize=100_000)(self._lookup)

    def _candidates(self, host):
        """host, then each parent up to (and including) the registrable domain."""
        if _is_ip(host):
            return []
        ext = _extract(host)
        base = ext.top_domain_under_public_suffix
        if not base:
            return [host]
        labels = host.split(".")
        out = []
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            out.append(cand)
            if cand == base:
                break
        return out

    def _lookup(self, host):
        """-> (category, matched_domain) or None."""
        for cand in self._candidates(normalize(host)):
            row = self.con.execute("SELECT category FROM w WHERE domain=?", (cand,)).fetchone()
            if row:
                return row[0], cand
        return None

    def count(self):
        return self.con.execute("SELECT COUNT(*) FROM w").fetchone()[0]
