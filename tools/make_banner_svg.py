"""Write assets/banner.svg (the README header) from the terminal banner art."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guardian.banner import ART, BLUE, SHADOW, TAGLINE

CW, CH = 12, 22          # one character cell
PAD, OFF = 28, 5         # outer padding, shadow offset
lines = ART.splitlines()
cols = max(map(len, lines))


def hexc(rgb):
    return "#%02x%02x%02x" % rgb


def runs():
    """Horizontal runs of █ as (x, y, width) in pixels, merged so there are no seams."""
    for r, line in enumerate(lines):
        c = 0
        while c < len(line):
            if line[c] == "█":
                s = c
                while c < len(line) and line[c] == "█":
                    c += 1
                yield PAD + s * CW, PAD + r * CH, (c - s) * CW
            else:
                c += 1


W = PAD * 2 + cols * CW + OFF
H = PAD * 2 + len(lines) * CH + OFF + 34
rs = list(runs())
shadow = "".join(f'<rect x="{x + OFF}" y="{y + OFF}" width="{w}" height="{CH}"/>' for x, y, w in rs)
main = "".join(f'<rect x="{x}" y="{y}" width="{w}" height="{CH}"/>' for x, y, w in rs)
svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
       f'role="img" aria-label="GUARDIAN">'
       f'<rect width="{W}" height="{H}" rx="12" fill="#0d1117"/>'
       f'<g fill="none" stroke="{hexc(SHADOW)}" stroke-width="1.5">{shadow}</g>'
       f'<g fill="{hexc(BLUE)}" shape-rendering="crispEdges">{main}</g>'
       f'<text x="{PAD}" y="{H - PAD + 4}" fill="#8b949e" font-family="monospace" font-size="16">'
       f'{TAGLINE}</text></svg>\n')
out = Path(__file__).resolve().parents[1] / "assets" / "banner.svg"
out.parent.mkdir(exist_ok=True)
out.write_text(svg, encoding="utf-8")
print(out, len(rs), "runs")
