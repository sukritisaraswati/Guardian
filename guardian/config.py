import json
import os
from pathlib import Path

HOME = Path(os.environ.get("GUARDIAN_HOME", Path.home() / ".guardian"))
STATE_FILE = HOME / "state.json"
DB_FILE = HOME / "whitelist.db"
LOG_FILE = HOME / "guardian.log"
PROXY_LOG = HOME / "proxy.log"
DATA_CSV = Path(__file__).parent / "data" / "whitelist.csv.gz"

HOST = "127.0.0.1"
PORT = 8899

CONFIG_FILE = HOME / "config.json"
PHISHTANK_FILE = HOME / "phishtank.csv"

CATEGORIZE_TIMEOUT = 4  # seconds to fetch a homepage when categorizing (runs in the background)

# Phase 2: hard limit on the online lookups (Google Safe Browsing + VirusTotal) per URL.
PHASE2_TIMEOUT = float(os.environ.get("GUARDIAN_PHASE2_TIMEOUT", "1.5"))
# VirusTotal engines that must flag a URL before it counts as malicious (1 gives more false alarms).
VT_MIN_DETECTIONS = int(os.environ.get("GUARDIAN_VT_MIN", "2"))
PROCEED_TTL = 3600  # seconds a "Continue anyway" choice lasts for that site
FEED_UPDATE = os.environ.get("GUARDIAN_NO_FEED") != "1"
FEED_REFRESH = 3 * 3600

KEY_ENV = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "safebrowsing": "GOOGLE_SAFE_BROWSING_API_KEY",
    "phishtank": "PHISHTANK_APP_KEY",  # optional: PhishTank works without it, with lower download limits
}


def _file_keys():
    try:
        return json.loads(CONFIG_FILE.read_text()).get("keys", {})
    except Exception:
        return {}


def get_key(name):
    """API key from the environment, else from ~/.guardian/config.json."""
    return os.environ.get(KEY_ENV[name]) or _file_keys().get(name) or None


def set_key(name, value):
    HOME.mkdir(parents=True, exist_ok=True)
    keys = _file_keys()
    keys[name] = value
    CONFIG_FILE.write_text(json.dumps({"keys": keys}, indent=2))
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass
