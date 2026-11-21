#!/usr/bin/env python3
"""Bake assets/icons_sources/about_band.svg into ce_apps/cerf_demo/band_data.h.

Usage: python tools/gen_cerf_demo_band.py [about_band.svg]

Emits cerf_band_rgb[W*H*3] as row-major top-down R,G,B bytes, matching the
consumer in ce_apps/cerf_demo/main.c: bits[i] = (s[0]<<16)|(s[1]<<8)|s[2].
Rendered at the SVG's intrinsic width/height (the demo StretchBlts it to the
dialog width, so only the band's own aspect ratio matters).
"""

import sys
from pathlib import Path

from product_facts import ABOUT_BAND_ASSET, ASSET_ICONS_DIR
from svg_raster import intrinsic_size, render_svg

REPO = Path(__file__).resolve().parent.parent
DEFAULT_SVG = REPO / "assets" / ASSET_ICONS_DIR / (ABOUT_BAND_ASSET + ".svg")
OUT = REPO / "ce_apps" / "cerf_demo" / "band_data.h"


def main() -> int:
    svg = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SVG
    w, h = intrinsic_size(svg.read_text(encoding="utf-8"))
    data = render_svg(svg, w, h, "RGB").tobytes()

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
