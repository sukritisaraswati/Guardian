"""Layer 2 (reputation databases) and Layer 3 (sandbox) plug in here.

Phase 1 hands every non-whitelisted URL to `analyze`. Until Phase 2 is built it just applies
the configured default (config.UNKNOWN_ACTION) so the pipeline works end to end.
"""
from dataclasses import dataclass

from . import config


@dataclass
class Verdict:
    action: str      # "allow" | "block"
    layer: int       # 1 = whitelist, 2 = reputation, 3 = sandbox, 0 = default policy
    reason: str
    category: str


def analyze(url, category):
    # TODO(phase 2): VirusTotal / Google Safe Browsing / PhishTank, then the sandbox.
    return Verdict(config.UNKNOWN_ACTION, 0, "not whitelisted; phase 2 not implemented", category)
