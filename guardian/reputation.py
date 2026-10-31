"""Layer 2: is this URL a known threat? PhishTank (local feed), Google Safe Browsing, VirusTotal."""
import base64
import bz2
import csv
import io
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import config

log = logging.getLogger("guardian")

GSB = "Google Safe Browsing"
VT = "VirusTotal"
PT = "PhishTank"

csv.field_size_limit(10_000_000)


RISK = {0: 0, 1: 33, 2: 66, 3: 100}


class Unavailable(Exception):
    """A source could not answer (no key, rate limit, timeout, network error)."""


@dataclass
class Result:
    found: bool = False
    sources: list = field(default_factory=list)      # sources that flagged the URL
    checked: list = field(default_factory=list)      # sources that answered
    unavailable: list = field(default_factory=list)  # sources that could not answer

    @property
    def risk(self):
        """Percent chance of being malicious: flagged by 1 of 3 sources = 33, 2 = 66, 3 = 100."""
        return RISK[min(len(self.sources), 3)]


# ---- PhishTank: local copy of the public feed ---------------------------------------------
def url_key(url):
    s = urlsplit(url.strip())
    return ((s.hostname or "").lower() + (s.path or "/") + (("?" + s.query) if s.query else "")).rstrip("/")


class PhishTank:
    def __init__(self):
        self.keys = frozenset()
        self.loaded = False

    def load(self, text):
        keys = set()
        rd = csv.reader(io.StringIO(text))
        header = next(rd, [])
        i = header.index("url") if "url" in header else 1
        for row in rd:
            if len(row) > i:
                keys.add(url_key(row[i]))
        self.keys, self.loaded = frozenset(keys), True

    def load_file(self):
        try:
            self.load(config.PHISHTANK_FILE.read_text(encoding="utf-8", errors="ignore"))
        except FileNotFoundError:
            pass

    def contains(self, url):
        k = url_key(url)
        return k in self.keys or k.split("?")[0] in self.keys


phishtank = PhishTank()


def _download_feed():
    key = config.get_key("phishtank")
    base = "http://data.phishtank.com/data/" + (key + "/" if key else "") + "online-valid.csv.bz2"
    req = urllib.request.Request(base, headers={"User-Agent": "phishtank/guardian"})
    data = bz2.decompress(urllib.request.urlopen(req, timeout=120).read())
    tmp = config.PHISHTANK_FILE.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(config.PHISHTANK_FILE)


def _feed_loop():
    phishtank.load_file()
    while True:
        try:
            age = time.time() - config.PHISHTANK_FILE.stat().st_mtime
        except FileNotFoundError:
            age = float("inf")
        if age > config.FEED_REFRESH:
            try:
                _download_feed()
                phishtank.load_file()
                log.info("PhishTank feed updated: %d URLs", len(phishtank.keys))
            except Exception as e:
                log.info("PhishTank feed update failed: %s", e)
        time.sleep(1800)


def start_feed_updates():
    if config.FEED_UPDATE:
        threading.Thread(target=_feed_loop, daemon=True).start()
    else:
        phishtank.load_file()


# ---- Online sources -----------------------------------------------------------------------
def _gsb(url):
    key = config.get_key("safebrowsing")
    if not key:
        raise Unavailable("no key")
    body = json.dumps({
        "client": {"clientId": "guardian", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]}}).encode()
    req = urllib.request.Request(
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + key, data=body,
        headers={"Content-Type": "application/json"})
    try:
        out = json.load(urllib.request.urlopen(req, timeout=config.PHASE2_TIMEOUT + 1))
    except Exception as e:
        raise Unavailable(str(e))
    return bool(out.get("matches"))


_vt_calls = deque()
_vt_lock = threading.Lock()


def _vt_allowed():
    """Free VirusTotal keys allow 4 lookups per minute; don't burn requests we know will fail."""
    with _vt_lock:
        now = time.time()
        while _vt_calls and now - _vt_calls[0] > 60:
            _vt_calls.popleft()
        if len(_vt_calls) >= 4:
            return False
        _vt_calls.append(now)
        return True


def _vt(url):
    key = config.get_key("virustotal")
    if not key:
        raise Unavailable("no key")
    if not _vt_allowed():
        raise Unavailable("rate limit")
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    req = urllib.request.Request("https://www.virustotal.com/api/v3/urls/" + uid, headers={"x-apikey": key})
    try:
        data = json.load(urllib.request.urlopen(req, timeout=config.PHASE2_TIMEOUT + 1))
    except urllib.error.HTTPError as e:
        if e.code == 404:  # VirusTotal has never seen this URL
            return False
        raise Unavailable(f"HTTP {e.code}")
    except Exception as e:
        raise Unavailable(str(e))
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return stats.get("malicious", 0) >= config.VT_MIN_DETECTIONS


# ---- Combined check -----------------------------------------------------------------------
_pool = ThreadPoolExecutor(8)
_cache = {}      # url -> (expires, Result)
_bad_hosts = {}  # host -> expires, so sub-resources of a known-bad site are stopped too
FOUND_TTL, CLEAN_TTL, PARTIAL_TTL = 6 * 3600, 1800, 60


def _store(url, r):
    ttl = FOUND_TTL if r.found else (PARTIAL_TTL if r.unavailable else CLEAN_TTL)
    _cache[url] = (time.time() + ttl, r)
    if r.found:
        _bad_hosts[(urlsplit(url).hostname or "").lower()] = (time.time() + FOUND_TTL, list(r.sources))


def check(url, quick=False):
    """-> Result. Asks every source (within the time limit) so the risk score counts all of them.
    quick=True never touches the network (cache + PhishTank only), for sub-resources."""
    now = time.time()
    hit = _cache.get(url)
    if hit and hit[0] > now:
        return hit[1]
    host = (urlsplit(url).hostname or "").lower()
    bad = _bad_hosts.get(host)
    if bad and bad[0] > now:
        return Result(True, list(bad[1]))

    r = Result()
    if phishtank.loaded:
        r.checked.append(PT)
        if phishtank.contains(url):
            r.found = True
            r.sources.append(PT)
    else:
        r.unavailable.append(PT)
    if quick:
        return r  # not cached: the page itself still gets the full check

    futs = {_pool.submit(_gsb, url): GSB, _pool.submit(_vt, url): VT}
    done, pending = wait(futs, timeout=max(0, now + config.PHASE2_TIMEOUT - time.time()))
    for f in futs:
        if f not in done:
            continue
        try:
            flagged = f.result()
        except Exception:
            r.unavailable.append(futs[f])
            continue
        r.checked.append(futs[f])
        if flagged:
            r.found = True
            r.sources.append(futs[f])
    r.unavailable += [futs[f] for f in pending]
    for f in pending:
        f.cancel()
    _store(url, r)
    return r
