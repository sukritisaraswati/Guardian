"""The decision funnel for one URL: whitelist (layer 1) -> reputation (layer 2) -> sandbox (layer 3, todo)."""
import logging
import threading
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
            return Verdict("allow", 1, "no host")
        if whitelist.is_local(host):
            return Verdict("allow", 1, "local address")
        hit = self.wl.lookup(host)
        if hit:
            return Verdict("allow", 1, f"whitelisted ({hit[1]})", category=hit[0])
        return None

    def analyze(self, url, quick=False):
        """Phase 2 for a URL that is not whitelisted. quick=True is for sub-resources (no network)."""
        v = phase2.analyze(url, quick=quick)
        if not quick:
            log.info("%s %s | %s", v.action.upper(), url, v.reason)
            # Categorize in the background: it fetches the homepage, so it must not delay the page.
            threading.Thread(target=self._categorize, args=(url,), daemon=True).start()
        elif v.action != "allow":
            log.info("%s %s | %s", v.action.upper(), url, v.reason)
        return v

    @staticmethod
    def _categorize(url):
        host = whitelist.normalize(urlsplit(url).hostname or "")
        log.info("CATEGORY %s -> %s", host, categorize(host))
