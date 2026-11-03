"""Zip the extension for the Chrome Web Store or for sharing: dist/guardian-extension-<version>.zip

Run from the repo root:  python tools/pack_extension.py
"""
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "extension"
version = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))["version"]
out = ROOT / "dist" / f"guardian-extension-{version}.zip"
out.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for f in sorted(EXT.rglob("*")):
        if f.is_file():
            z.write(f, f.relative_to(EXT).as_posix())
print(out, f"{out.stat().st_size / 1e6:.1f} MB")
