import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from . import __version__, banner, config, sysproxy, whitelist

MITMDUMP = "from mitmproxy.tools.main import mitmdump; mitmdump()"


def _load_state():
    try:
        return json.loads(config.STATE_FILE.read_text())
    except Exception:
        return None


def _alive(pid):
    if sys.platform == "win32":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _kill(pid):
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass


def _port_open(port):
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex((config.HOST, port)) == 0


def cmd_start(a):
    banner.show()
    st = _load_state()
    if st:
        if _alive(st["pid"]):
            print(f"Guardian is already running (pid {st['pid']}, port {st['port']}).")
            return 0
        sysproxy.restore(st.get("prev_proxy"))  # previous run died without `guardian stop`
        config.STATE_FILE.unlink(missing_ok=True)

    config.HOME.mkdir(parents=True, exist_ok=True)
    if whitelist.ensure_db():
        print("Built the whitelist database (first run only).")
    if _port_open(a.port):
        print(f"Port {a.port} is already in use. Try: guardian start --port <other>")
        return 1

    cmd = [sys.executable, "-c", MITMDUMP,
           "--listen-host", config.HOST, "--listen-port", str(a.port),
           "-s", str(Path(__file__).with_name("addon.py")), "-q"]
    log = open(config.PROXY_LOG, "ab")
    kw = {}
    if sys.platform == "win32":
        kw["creationflags"] = 0x00000008 | 0x00000200 | 0x08000000  # DETACHED | NEW_GROUP | NO_WINDOW
    else:
        kw["start_new_session"] = True
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                            **kw)

    for _ in range(60):
        if _port_open(a.port):
            break
        if proc.poll() is not None:
            print(f"Proxy failed to start. See {config.PROXY_LOG}")
            return 1
        time.sleep(0.5)
    else:
        _kill(proc.pid)
        print(f"Proxy did not come up. See {config.PROXY_LOG}")
        return 1

    prev = None if a.no_system_proxy else sysproxy.enable(config.HOST, a.port)
    config.STATE_FILE.write_text(json.dumps({"pid": proc.pid, "port": a.port, "prev_proxy": prev}))
    print(f"Guardian started on {config.HOST}:{a.port}.")
    if a.no_system_proxy:
        print(f"System proxy NOT changed: point your browser at {config.HOST}:{a.port}.")
    if not (Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem").exists():
        print("HTTPS note: run `guardian install-cert` once so browsers trust Guardian's certificate.")
    _print_sources()
    print("Run `guardian stop` to stop.")
    return 0


def _print_sources():
    names = {"virustotal": "VirusTotal", "safebrowsing": "Google Safe Browsing"}
    missing = [f"{n} (guardian set-key {k} <key>)" for k, n in names.items() if not config.get_key(k)]
    print("Reputation sources: PhishTank (local feed)" + "".join(
        f", {n}" for k, n in names.items() if config.get_key(k)))
    if missing:
        print("Not configured: " + "; ".join(missing))


def cmd_set_key(a):
    config.set_key(a.service, a.key)
    print(f"Saved {a.service} key. Restart Guardian (stop, start) to use it.")
    return 0


def cmd_stop(a):
    st = _load_state()
    if not st:
        print("Guardian is not running.")
        return 0
    sysproxy.restore(st.get("prev_proxy"))
    _kill(st["pid"])
    config.STATE_FILE.unlink(missing_ok=True)
    print("Guardian stopped. Your previous proxy settings are restored.")
    return 0


def cmd_status(a):
    banner.show()
    st = _load_state()
    if st and _alive(st["pid"]):
        print(f"running (pid {st['pid']}, port {st['port']}); log: {config.LOG_FILE}")
    else:
        print("stopped")
    _print_sources()
    return 0


def cmd_install_cert(a):
    ca = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if not ca.exists():  # mitmproxy writes it on first launch
        print("Generating the certificate (starting the proxy briefly)...")
        p = subprocess.Popen([sys.executable, "-c", MITMDUMP, "--listen-port", "0", "-q"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(30):
            if ca.exists():
                break
            time.sleep(0.5)
        p.terminate()
    if sys.platform == "win32":
        rc = subprocess.run(["certutil", "-addstore", "-user", "Root", str(ca)]).returncode
        _firefox_use_os_store()
        return rc
    if sys.platform == "darwin":
        print(f"Run: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {ca}")
        _firefox_use_os_store()
        return 0
    return _linux_install_cert(ca)


def _firefox_profiles():
    roots = [Path.home() / ".mozilla" / "firefox", Path.home() / "snap" / "firefox" / "common" / ".mozilla" / "firefox",
             Path.home() / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox",
             Path.home() / "Library" / "Application Support" / "Firefox" / "Profiles",
             Path(os.environ.get("APPDATA", "~")) / "Mozilla" / "Firefox" / "Profiles"]
    return [d for r in roots if r.is_dir() for d in r.iterdir() if (d / "prefs.js").exists()]


def _firefox_use_os_store():
    """Windows/macOS: make Firefox trust certificates from the OS store (where Guardian's now is)."""
    line = 'user_pref("security.enterprise_roots.enabled", true);\n'
    for prof in _firefox_profiles():
        uj = prof / "user.js"
        old = uj.read_text(encoding="utf-8") if uj.exists() else ""
        if "security.enterprise_roots.enabled" not in old:
            uj.write_text(old + line, encoding="utf-8")
            print(f"Firefox profile {prof.name}: set to trust the OS certificate store.")
    print("Restart your browser.")


def _linux_install_cert(ca):
    import shutil
    ok = True
    certutil = shutil.which("certutil")
    if not certutil:
        print("Missing `certutil`. Install it, then run `guardian install-cert` again:\n"
              "  sudo apt install libnss3-tools      (Debian/Ubuntu/Kali)\n"
              "  sudo dnf install nss-tools          (Fedora)")
        ok = False
    else:
        dbs = _firefox_profiles()
        chrome = Path.home() / ".pki" / "nssdb"
        if not chrome.exists():
            chrome.mkdir(parents=True)
            subprocess.run([certutil, "-N", "-d", f"sql:{chrome}", "--empty-password"], capture_output=True)
        dbs.append(chrome)
        for db in dbs:
            subprocess.run([certutil, "-D", "-n", "Guardian", "-d", f"sql:{db}"], capture_output=True)
            r = subprocess.run([certutil, "-A", "-n", "Guardian", "-t", "C,,", "-i", str(ca), "-d", f"sql:{db}"],
                               capture_output=True, text=True)
            name = "Chromium/Chrome" if db == chrome else f"Firefox profile {db.name}"
            print(f"{name}: {'trusted' if r.returncode == 0 else 'FAILED ' + r.stderr.strip()}")
            ok &= r.returncode == 0
        if not _firefox_profiles():
            print("No Firefox profile found. Open Firefox once, close it, then run this again.")
    print("For other programs (curl, Python...), also run:\n"
          f"  sudo cp {ca} /usr/local/share/ca-certificates/guardian.crt && sudo update-ca-certificates")
    print("Restart your browser.")
    return 0 if ok else 1


def cmd_rebuild(a):
    whitelist.ensure_db(force=True)
    print("Whitelist database rebuilt.")
    return 0


def main():
    p = argparse.ArgumentParser(prog="guardian", description="Guardian URL threat detection")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("start", help="start protecting")
    s.add_argument("--port", type=int, default=config.PORT)
    s.add_argument("--no-system-proxy", action="store_true", help="don't change OS proxy settings")
    s.set_defaults(fn=cmd_start)
    sub.add_parser("stop", help="stop and restore proxy settings").set_defaults(fn=cmd_stop)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("install-cert", help="trust Guardian's HTTPS certificate").set_defaults(fn=cmd_install_cert)
    k = sub.add_parser("set-key", help="save an API key for a reputation service")
    k.add_argument("service", choices=["virustotal", "safebrowsing", "phishtank"])
    k.add_argument("key")
    k.set_defaults(fn=cmd_set_key)
    sub.add_parser("rebuild-db").set_defaults(fn=cmd_rebuild)
    a = p.parse_args()
    if not a.cmd:  # plain `guardian`
        banner.show()
        p.print_help()
        sys.exit(0)
    sys.exit(a.fn(a))
