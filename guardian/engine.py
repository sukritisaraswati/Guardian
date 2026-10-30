"""The decision funnel for one URL: whitelist -> (phase 2)."""
import logging
from urllib.parse import urlsplit

from . import phase2, whitelist
from .categorizer import categorize
from .phase2 import Verdict

log = logging.getLogger("guardian")


class Engine:
    def __init__(self):
        self.wl = whitelist.Whitelist()

    def check_whitelist(self, url):
        """Fast, non-blocking. -> Verdict if the URL may pass, else None."""
        host = whitelist.normalize(urlsplit(url).hostname or "")
        if not host:
            return Verdict("allow", 1, "no host", "-")
        if whitelist.is_local(host):
            return Verdict("allow", 1, "local address", "-")
        hit = self.wl.lookup(host)
        if hit:
            return Verdict("allow", 1, f"whitelisted ({hit[1]})", hit[0])
        return None

    def check_unknown(self, url):
        """Blocking (fetches the homepage). Categorize, then hand to phase 2."""
        host = whitelist.normalize(urlsplit(url).hostname or "")
        category = categorize(host)
        v = phase2.analyze(url, category)
        log.info("%s %s | %s | %s", v.action.upper(), url, category, v.reason)
        return v
