"""mitmproxy addon: every request goes through the Guardian funnel."""
import asyncio
import hashlib
import hmac
import logging
import secrets
import time
from urllib.parse import quote, urlsplit

from mitmproxy import http, tls

from guardian import config, pages, reputation
from guardian.engine import Engine

config.HOME.mkdir(parents=True, exist_ok=True)
_h = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
_h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
_log = logging.getLogger("guardian")
_log.addHandler(_h)
_log.setLevel(logging.INFO)

PROCEED_HOST = "guardian.invalid"  # never resolves; the addon answers it itself


def is_navigation(flow):
    """True when the user is opening a page (not an image/script/XHR loaded by a page)."""
    h = flow.request.headers
    dest = h.get("Sec-Fetch-Dest")
    if dest:  # browsers send this on HTTPS requests
        return dest == "document"
    return flow.request.method == "GET" and "text/html" in h.get("Accept", "")


class Guardian:
    def __init__(self):
        self.engine = Engine()
        self.secret = secrets.token_hex(16)
        self.allowed = {}  # host -> expiry, set by "Continue anyway"
        reputation.start_feed_updates()

    def _token(self, host):
        return hmac.new(self.secret.encode(), host.encode(), hashlib.sha256).hexdigest()[:32]

    def _proceed(self, flow):
        target = flow.request.query.get("u", "")
        host = urlsplit(target).hostname or ""
        if host and target.startswith(("http://", "https://")) and \
                hmac.compare_digest(flow.request.query.get("t", ""), self._token(host)):
            self.allowed[host] = time.time() + config.PROCEED_TTL
            flow.response = http.Response.make(302, b"", {"Location": target})
        else:
            flow.response = http.Response.make(400, b"Invalid Guardian request")

    def tls_clienthello(self, data: tls.ClientHelloData):
        """Whitelisted HTTPS sites are tunnelled untouched: no decryption, no Guardian certificate,
        so they load exactly as they would without Guardian. Only other sites are opened up,
        which is what lets Guardian show its warning page inside them."""
        host = data.client_hello.sni or (data.context.server.address or ("",))[0]
        if not host:
            return
        if self.engine.check_whitelist(f"https://{host}/") or self.allowed.get(host, 0) > time.time():
            data.ignore_connection = True

    async def request(self, flow: http.HTTPFlow):
        req = flow.request
        if req.pretty_host == PROCEED_HOST:
            return self._proceed(flow)
        url = req.pretty_url
        if self.engine.check_whitelist(url):
            return
        host = req.pretty_host
        if self.allowed.get(host, 0) > time.time():
            return
        nav = is_navigation(flow)
        v = await asyncio.get_running_loop().run_in_executor(None, self.engine.analyze, url, not nav)

        hdr = {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}
        if v.action == "block":
            if nav:
                flow.response = http.Response.make(403, pages.malicious(url, v.sources, v.risk, v.unavailable), hdr)
            else:
                flow.response = http.Response.make(403, b"Blocked by Guardian")
        elif v.action == "warn":
            proceed = f"http://{PROCEED_HOST}/proceed?u={quote(url, safe='')}&t={self._token(host)}"
            flow.response = http.Response.make(403, pages.suspicious(url, v.unavailable, proceed), hdr)


addons = [Guardian()]
