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

# What to do with a URL that is NOT whitelisted until Phase 2 exists.
# "allow" = let it through and log it, "block" = stop it.
UNKNOWN_ACTION = os.environ.get("GUARDIAN_UNKNOWN_ACTION", "allow")
CATEGORIZE_TIMEOUT = 4  # seconds to fetch a homepage when categorizing
