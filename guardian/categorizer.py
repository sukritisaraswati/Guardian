"""Categorize a site that is not in the whitelist, from its homepage title/description."""
import re
import ssl
import urllib.request

from . import config
from ._scorer import classify

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_cache = {}


def categorize(host):
    """-> category name, or "Uncategorized" if the site can't be read or isn't clear."""
    if host in _cache:
        return _cache[host]
    cat = "Uncategorized"
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}", headers={"User-Agent": "Mozilla/5.0 Guardian"})
            body = urllib.request.urlopen(req, timeout=config.CATEGORIZE_TIMEOUT, context=_ctx).read(40000).decode("utf-8", "ignore")
        except Exception:
            continue
        t = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', body, re.I | re.S)
        rec = {"title": re.sub(r"\s+", " ", t.group(1)).strip()[:150] if t else "",
               "desc": re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""}
        x = classify(rec)
        if x:
            cat = x[0]
        break
    _cache[host] = cat
    return cat
