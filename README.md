# Guardian

Proactive URL threat detection. Guardian runs as a local proxy and checks every URL you visit.

**Phase 1 (this version):** Layer 1 whitelist. A site in the whitelist database loads normally. Anything else is categorized and handed to Phase 2 (reputation databases, then the sandbox), which is not built yet.

## Install

```
git clone <repo-url>
cd Guardian
pip install .
```

Needs Python 3.9+.

## Use

```
guardian start        # start protecting (sets the OS proxy)
guardian stop         # stop and restore your previous proxy settings
guardian status
```

First time only, so HTTPS sites work through the proxy:

```
guardian install-cert
```

On Windows this adds Guardian's certificate to your user trust store (Windows asks you to confirm). Firefox uses its own store; import `~/.mitmproxy/mitmproxy-ca-cert.pem` there.

Options for `start`: `--port 8899`, `--no-system-proxy` (point the browser at the proxy yourself), `--unknown allow|block` (what to do with non-whitelisted sites until Phase 2 exists; default `allow`).

If Guardian crashes, run `guardian stop` (or `guardian start` again) to restore your proxy settings.

## How a URL is handled

1. Every request goes through the proxy.
2. The host is matched against the whitelist: the exact host, then its parents up to the registrable domain (`mail.google.com` matches `google.com`). Shared-hosting suffixes such as `github.io` and `blogspot.com` are not inherited, so `user.github.io` is not trusted just because `github.io` is.
3. Whitelisted: the site loads normally. Local addresses also pass.
4. Not whitelisted: the site is categorized from its homepage title and description, then passed to `guardian/phase2.py` (a placeholder until Phase 2 is built).

Decisions for non-whitelisted URLs are logged to `~/.guardian/guardian.log`.

## Whitelist data

`guardian/data/whitelist.csv.gz` (`domain,category`) is built from `database.csv` by `tools/build_whitelist.py`. On first start it is loaded into SQLite at `~/.guardian/whitelist.db`. Categories of about 565k entries were not verified (see `categorization_review_report.md`), but matching depends only on the domain.

## Tests

```
pip install pytest
python -m pytest tests
```
