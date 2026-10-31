"""Phase 2: reputation check. Found in PhishTank / Safe Browsing / VirusTotal -> malicious, with a
risk of 33% / 66% / 100% for 1 / 2 / 3 sources.
Not found anywhere -> "may be malicious" (the site is not whitelisted and nobody vouches for it).
Layer 3 (the sandbox) will take over the "may be malicious" case.
"""
from dataclasses import dataclass, field

from . import reputation


@dataclass
class Verdict:
    action: str      # "allow" | "warn" | "block"
    layer: int       # 1 = whitelist, 2 = reputation, 3 = sandbox
    reason: str
    category: str = "-"
    sources: list = field(default_factory=list)
    unavailable: list = field(default_factory=list)
    risk: int = 0    # percent, from how many of the 3 sources flagged the URL


def analyze(url, quick=False):
    r = reputation.check(url, quick=quick)
    if r.found:
        return Verdict("block", 2, f"known malicious ({r.risk}%): " + ", ".join(r.sources),
                       sources=r.sources, unavailable=r.unavailable, risk=r.risk)
    if quick:  # a sub-resource of a page; the page itself is checked in full
        return Verdict("allow", 2, "no local match", unavailable=r.unavailable)
    return Verdict("warn", 2, "not found in any reputation source", sources=[],
                   unavailable=r.unavailable)
