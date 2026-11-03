"""Write assets/banner.svg (the README header) and extension/icons/banner.svg (letters only, transparent) from the terminal banner art."""
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


def runs(pad):
    """Horizontal runs of █ as (x, y, width) in pixels, merged so there are no seams."""
    for r, line in enumerate(lines):
        c = 0
        while c < len(line):
            if line[c] == "█":
                s = c
                while c < len(line) and line[c] == "█":
                    c += 1
                yield pad + s * CW, pad + r * CH, (c - s) * CW
            else:
                c += 1


def build(pad, framed):
    """framed: dark card with the tagline (README). Not framed: just the letters on a transparent background."""
    W = pad * 2 + cols * CW + OFF
    H = pad * 2 + len(lines) * CH + OFF + (34 if framed else 0)
    rs = list(runs(pad))
    shadow = "".join(f'<rect x="{x + OFF}" y="{y + OFF}" width="{w}" height="{CH}"/>' for x, y, w in rs)
    main = "".join(f'<rect x="{x}" y="{y}" width="{w}" height="{CH}"/>' for x, y, w in rs)
    bg = f'<rect width="{W}" height="{H}" rx="12" fill="#0d1117"/>' if framed else ""
    tag = (f'<text x="{pad}" y="{H - pad + 4}" fill="#8b949e" font-family="monospace" font-size="16">'
           f'{TAGLINE}</text>') if framed else ""
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
           f'role="img" aria-label="GUARDIAN">{bg}'
           f'<g fill="none" stroke="{hexc(SHADOW)}" stroke-width="1.5">{shadow}</g>'
           f'<g fill="{hexc(BLUE)}" shape-rendering="crispEdges">{main}</g>{tag}</svg>' + chr(10))
    return svg, len(rs)


root = Path(__file__).resolve().parents[1]
for rel, pad, framed in (("assets/banner.svg", PAD, True), ("extension/icons/banner.svg", 4, False)):
    out = root / rel
    out.parent.mkdir(exist_ok=True)
    svg, n = build(pad, framed)
    out.write_text(svg, encoding="utf-8")
    print(out, n, "runs")
