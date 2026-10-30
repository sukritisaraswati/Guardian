"""Point the OS at the Guardian proxy and restore the previous settings afterwards."""
import subprocess
import sys


def enable(host, port):
    """-> dict of the previous settings (pass it to restore())."""
    if sys.platform == "win32":
        return _win_enable(host, port)
    if sys.platform == "darwin":
        return _mac_enable(host, port)
    return _linux_enable(host, port)


def restore(prev):
    if not prev:
        return
    {"win32": _win_restore, "darwin": _mac_restore}.get(prev.get("os"), _linux_restore)(prev)


# ---- Windows ---------------------------------------------------------------------------
_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _win_notify():
    import ctypes
    w = ctypes.windll.wininet
    w.InternetSetOptionW(None, 39, None, 0)  # settings changed
    w.InternetSetOptionW(None, 37, None, 0)  # refresh


def _win_get(k, name):
    import winreg
    try:
        return list(winreg.QueryValueEx(k, name))
    except FileNotFoundError:
        return None


def _win_enable(host, port):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_ALL_ACCESS) as k:
        prev = {"os": "win32", "ProxyEnable": _win_get(k, "ProxyEnable"),
                "ProxyServer": _win_get(k, "ProxyServer"), "ProxyOverride": _win_get(k, "ProxyOverride")}
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
        winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    _win_notify()
    return prev


def _win_restore(prev):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_ALL_ACCESS) as k:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
            old = prev.get(name)
            if old is None:
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(k, name, 0, old[1], old[0])
    _win_notify()


# ---- macOS (untested) ------------------------------------------------------------------
def _ns(*a):
    return subprocess.run(["networksetup", *a], capture_output=True, text=True).stdout


def _mac_enable(host, port):
    services = [s for s in _ns("-listallnetworkservices").splitlines()[1:] if s and not s.startswith("*")]
    prev = {"os": "darwin", "services": {}}
    for s in services:
        prev["services"][s] = {kind: _ns(f"-get{kind}", s) for kind in ("webproxy", "securewebproxy")}
        _ns("-setwebproxy", s, host, str(port))
        _ns("-setsecurewebproxy", s, host, str(port))
    return prev


def _mac_restore(prev):
    for s, kinds in prev["services"].items():
        for kind, out in kinds.items():
            d = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
            if d.get("Enabled") == "Yes":
                _ns(f"-set{kind}", s, d["Server"], d["Port"])
            else:
                _ns(f"-set{kind}state", s, "off")


# ---- Linux / GNOME (untested) ----------------------------------------------------------
def _gs(*a):
    return subprocess.run(["gsettings", *a], capture_output=True, text=True).stdout.strip()


def _linux_enable(host, port):
    prev = {"os": "linux", "mode": _gs("get", "org.gnome.system.proxy", "mode")}
    for p in ("http", "https"):
        _gs("set", f"org.gnome.system.proxy.{p}", "host", host)
        _gs("set", f"org.gnome.system.proxy.{p}", "port", str(port))
    _gs("set", "org.gnome.system.proxy", "mode", "manual")
    return prev


def _linux_restore(prev):
    _gs("set", "org.gnome.system.proxy", "mode", prev.get("mode", "none").strip("'") or "none")
