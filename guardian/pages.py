"""Warning pages shown in the browser in place of the requested page."""
from html import escape

_CSS = """
body{font-family:system-ui,sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;
justify-content:center;background:%(bg)s;color:#1a1a1a}
.card{max-width:560px;margin:16px;padding:32px;background:#fff;border-radius:12px;
box-shadow:0 4px 24px rgba(0,0,0,.2);border-top:8px solid %(accent)s}
h1{margin:0 0 12px;color:%(accent)s;font-size:26px}
p{line-height:1.5;margin:8px 0}.url{word-break:break-all;font-family:monospace;background:#f3f3f3;
padding:8px;border-radius:6px}
a.btn,button{display:inline-block;margin:16px 8px 0 0;padding:10px 18px;border-radius:6px;border:0;
font-size:15px;cursor:pointer;text-decoration:none}
.primary{background:%(accent)s;color:#fff}.secondary{background:#e8e8e8;color:#333}
small{color:#666}
"""


def _page(title, accent, bg, url, body, buttons):
    return (f"<!doctype html><meta charset=utf-8><title>{escape(title)}</title>"
            f"<style>{_CSS % {'accent': accent, 'bg': bg}}</style>"
            f"<div class=card><h1>{escape(title)}</h1><p class=url>{escape(url)}</p>{body}{buttons}"
            f"<p><small>Guardian</small></p></div>").encode()


_BACK = '<button class=primary onclick="history.length>1?history.back():window.close()">Go back</button>'


def malicious(url, sources):
    body = f"<p>This link is known to be dangerous. Flagged by: <b>{escape(', '.join(sources))}</b>.</p>"
    return _page("Link is malicious", "#c62828", "#ffebee", url, body, _BACK)


def suspicious(url, unavailable, proceed_url):
    body = ("<p>This site is not on Guardian's trusted list and was not found in VirusTotal, "
            "Google Safe Browsing or PhishTank. It may still be dangerous.</p>")
    if unavailable:
        body += f"<p><small>Could not check: {escape(', '.join(unavailable))}.</small></p>"
    buttons = _BACK + f'<a class="btn secondary" href="{escape(proceed_url)}">Continue anyway</a>'
    return _page("Alert: May be malicious", "#e65100", "#fff3e0", url, body, buttons)
