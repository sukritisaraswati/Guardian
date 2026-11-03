"""Build the data files shipped inside the Chrome extension.

  extension/data/domains.txt.gz   sorted (by UTF-8 bytes) whitelist domains, one per line
  extension/data/cats.bin         one byte per domain: index into categories.json
  extension/data/categories.json  category names
  extension/data/psl.dat          public-suffix rules (comments stripped)
  extension/icons/icon*.png       toolbar icons

Run from the repo root:  python tools/build_extension_data.py [path/to/public_suffix_list.dat]
The public-suffix list is downloaded from publicsuffix.org if no file is given.
"""
import csv
import gzip
import json
import math
import struct
import sys
import urllib.request
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "extension"


def whitelist():
    rows = {}
    with gzip.open(ROOT / "guardian" / "data" / "whitelist.csv.gz", "rt", encoding="utf-8", newline="") as f:
        rd = csv.reader(f)
        next(rd)
        for d, c in rd:
            if d and "\n" not in d:
                rows.setdefault(d, c)
    cats = sorted(set(rows.values()))
    assert len(cats) < 256
    order = sorted(rows, key=lambda d: d.encode("utf-8"))
    (OUT / "data").mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(OUT / "data" / "domains.txt.gz", "wb", compresslevel=9, mtime=0) as g:
        g.write("\n".join(order).encode("utf-8"))
    (OUT / "data" / "cats.bin").write_bytes(bytes(cats.index(rows[d]) for d in order))
    (OUT / "data" / "categories.json").write_text(json.dumps(cats), encoding="utf-8")
    print(len(order), "domains,", len(cats), "categories")


def psl(src):
    text = Path(src).read_text(encoding="utf-8") if src else \
        urllib.request.urlopen("https://publicsuffix.org/list/public_suffix_list.dat", timeout=60).read().decode("utf-8")
    rules = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("//")]
    (OUT / "data" / "psl.dat").write_text("\n".join(rules), encoding="utf-8")
    print(len(rules), "public-suffix rules")


# ---- icons: a blue shield, drawn without any imaging library -----------------------------
def _inside(x, y):
    """Shield outline in a 0..1 box."""
    if not (0.12 <= x <= 0.88 and 0.08 <= y <= 0.94):
        return False
    if y <= 0.50:
        return True
    half = 0.38 * (1 - ((y - 0.50) / 0.44) ** 1.6)
    return abs(x - 0.5) <= half


def _check(x, y):
    """A white tick inside the shield."""
    def seg(ax, ay, bx, by, w=0.055):
        dx, dy = bx - ax, by - ay
        t = max(0, min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
        return math.hypot(x - (ax + t * dx), y - (ay + t * dy)) <= w
    return seg(0.31, 0.50, 0.45, 0.64) or seg(0.45, 0.64, 0.70, 0.34)


def _png(size):
    ss = 4  # supersampling
    raw = bytearray()
    for py in range(size):
        raw.append(0)
        for px in range(size):
            cover = tick = 0
            for sy in range(ss):
                for sx in range(ss):
                    x, y = (px + (sx + .5) / ss) / size, (py + (sy + .5) / ss) / size
                    if _inside(x, y):
                        cover += 1
                        tick += _check(x, y)
            n = ss * ss
            a = round(255 * cover / n)
            t = tick / cover if cover else 0
            r, g, b = (round(59 + (255 - 59) * t), round(130 + (255 - 130) * t), round(246 + (255 - 246) * t))
            raw += bytes((r, g, b, a))

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


def icons():
    (OUT / "icons").mkdir(parents=True, exist_ok=True)
    for s in (16, 32, 48, 128):
        (OUT / "icons" / f"icon{s}.png").write_bytes(_png(s))
    print("icons written")


if __name__ == "__main__":
    whitelist()
    psl(sys.argv[1] if len(sys.argv) > 1 else None)
    icons()
