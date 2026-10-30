"""mitmproxy addon: every request goes through the Guardian funnel."""
import asyncio
import logging

from mitmproxy import http

from guardian import config
from guardian.engine import Engine

config.HOME.mkdir(parents=True, exist_ok=True)
_h = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
_h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
_log = logging.getLogger("guardian")
_log.addHandler(_h)
_log.setLevel(logging.INFO)


class Guardian:
    def __init__(self):
        self.engine = Engine()
        self.pending = {}  # host -> future, so one site is categorized once

    async def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        v = self.engine.check_whitelist(url)
        if v is None:
            host = flow.request.pretty_host
            fut = self.pending.get(host)
            if fut is None:
                fut = self.pending[host] = asyncio.ensure_future(
                    asyncio.get_running_loop().run_in_executor(None, self.engine.check_unknown, url))
            v = await fut
        if v.action == "block":
            flow.response = http.Response.make(
                403,
                f"<h1>Blocked by Guardian</h1><p>{flow.request.pretty_host}</p><p>{v.reason}</p>".encode(),
                {"Content-Type": "text/html; charset=utf-8"})


addons = [Guardian()]
