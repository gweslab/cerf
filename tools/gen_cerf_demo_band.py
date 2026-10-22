#!/usr/bin/env python3
"""Bake assets/icons_sources/about_band.svg into ce_apps/cerf_demo/band_data.h.

Usage: python tools/gen_cerf_demo_band.py [about_band.svg]

Emits cerf_band_rgb[W*H*3] as row-major top-down R,G,B bytes, matching the
consumer in ce_apps/cerf_demo/main.c: bits[i] = (s[0]<<16)|(s[1]<<8)|s[2].
Rendered at the SVG's intrinsic width/height (the demo StretchBlts it to the
dialog width, so only the band's own aspect ratio matters).
"""

import re
import sys
from io import BytesIO
from pathlib import Path

import resvg_py
from PIL import Image

REPO = Path(__file__).resolve().parent.parent
DEFAULT_SVG = REPO / "assets" / "icons_sources" / "about_band.svg"
OUT = REPO / "ce_apps" / "cerf_demo" / "band_data.h"


def intrinsic_size(svg_text):
    w = re.search(r'<svg[^>]*\bwidth="(\d+)"', svg_text)
    h = re.search(r'<svg[^>]*\bheight="(\d+)"', svg_text)
    if not (w and h):
        vb = re.search(r'viewBox="[\d.]+ [\d.]+ ([\d.]+) ([\d.]+)"', svg_text)
        if not vb:
            sys.exit("cannot determine SVG intrinsic size")
        return round(float(vb.group(1))), round(float(vb.group(2)))
    return int(w.group(1)), int(h.group(1))


def main() -> int:
    svg = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SVG
    w, h = intrinsic_size(svg.read_text(encoding="utf-8"))

    raw = resvg_py.svg_to_bytes(svg_path=str(svg), width=w, height=h)
    img = Image.open(BytesIO(bytes(raw))).convert("RGB")
    if img.size != (w, h):
        img = img.resize((w, h), Image.LANCZOS)
    data = img.tobytes()

    lines = [
        "/* Auto-generated asset. Do not hand-edit. */",
        "#ifndef CERF_BAND_RGB_INCLUDED",
        "#define CERF_BAND_RGB_INCLUDED",
        f"#define CERF_BAND_RGB_W {w}",
        f"#define CERF_BAND_RGB_H {h}",
        f"static const unsigned char cerf_band_rgb[{w}*{h}*3] = {{",
    ]
    per_line = 26
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        lines.append("  " + ",".join(str(b) for b in chunk) + ",")
    lines.append("};")
    lines.append("#endif")

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT} ({w}x{h})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
