"""The GUARDIAN banner shown in the terminal."""
import os
import sys

ART = r"""
 ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
""".strip("\n")
TAGLINE = "Proactive URL threat detection"

BLUE = (59, 130, 246)        # letters
SHADOW = (30, 64, 175)       # box-drawing shadow
RESET = "\033[0m"


def _color_ok():
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if sys.platform == "win32":  # turn on ANSI escape handling in the Windows console
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            return False
    return True


def _fg(rgb, truecolor):
    return "\033[38;2;%d;%d;%dm" % rgb if truecolor else ("\033[94m" if rgb == BLUE else "\033[34m")


def render(color=True):
    if not color:
        return f"{ART}\n  {TAGLINE}\n"
    tc = bool(os.environ.get("COLORTERM") in ("truecolor", "24bit") or os.environ.get("WT_SESSION")
              or sys.platform == "win32")
    blue, shadow = _fg(BLUE, tc), _fg(SHADOW, tc)
    lines = []
    for line in ART.splitlines():
        out, cur = [], None
        for ch in line:
            want = blue if ch == "█" else shadow
            if ch != " " and want != cur:
                out.append(want)
                cur = want
            out.append(ch)
        lines.append("".join(out) + RESET)
    return "\n".join(lines) + f"\n  {shadow}{TAGLINE}{RESET}\n"


def show():
    text = render(_color_ok())
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        print(text)
    except UnicodeEncodeError:  # console that can't print block characters
        print(f"GUARDIAN - {TAGLINE}\n")
