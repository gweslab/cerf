#!/usr/bin/env python3
import argparse
import sys
from io import BytesIO
from pathlib import Path

from ico_format import (WIN16_PALETTE, build_ico, dib_frame,
                        dib_frame_indexed)
from product_facts import (ASSET_ICONS_DIR, BADGE_PREFIX, ERROR_ASSET, FONT_SANS_BOLD, FONTS_DIR, LOGO_ASSET,
                           LOGO_PNG, LOGO_PX)

DEFAULT_SIZES = [16, 20, 24, 32, 48, 64, 256]

REPO = Path(__file__).resolve().parent.parent
SRC_DIR = REPO / "assets" / ASSET_ICONS_DIR
ICO_DIR = REPO / "assets"

ICO_STEMS = (LOGO_ASSET, ERROR_ASSET)

CE_ICO_STEMS = (LOGO_ASSET,)
CE_ICO_SIZES = (16, 32)

CE2_ICO_SOURCES = {LOGO_ASSET: "cerf_vga"}
CE2_ICO_SIZES = (16, 32)
CE2_ICO_BPP = 4
CE2_ICO_DITHER = False

ANDROID_RES_DIR = REPO / "cerf-qt" / "mobile" / "android" / "res"
ANDROID_ICON_STEM = LOGO_ASSET
ANDROID_ICON_DENSITIES = (("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192))

TARGETS = ("ico", "ce_ico", "ce2_ico", "badges", "logo", "android")


def render_image(svg_path, size):
    """resvg-render svg_path at size*size, return a clean RGBA PIL Image."""
    import resvg_py
    from PIL import Image
    raw = resvg_py.svg_to_bytes(svg_path=str(svg_path), width=size, height=size)
    im = Image.open(BytesIO(bytes(raw))).convert("RGBA")
    if im.size != (size, size):
        im = im.resize((size, size), Image.LANCZOS)
    return im


def render_png(svg_path, size):
    """resvg-render svg_path at size*size, return a clean RGBA PNG blob."""
    buf = BytesIO()
    render_image(svg_path, size).save(buf, format="PNG")
    return buf.getvalue()


def render_dib(svg_path, size, ce_mask=False):
    return dib_frame(render_image(svg_path, size), ce_mask=ce_mask)


def render_dib_indexed(svg_path, size, bpp=4, dither=False, palette=None):
    return dib_frame_indexed(render_image(svg_path, size), bpp=bpp,
                             dither=dither, palette=palette)


def convert_ico(svg_path, sizes, out_dir):
    # 256 stays PNG: a 256x256 DIB frame is a quarter-megabyte per icon, and the
    # size is never selected for the status-bar / menu requests XP makes.
    frames = [(s, render_png(svg_path, s) if s >= 256 else render_dib(svg_path, s))
              for s in sizes]
    out_path = out_dir / (svg_path.stem + ".ico")
    out_path.write_bytes(build_ico(frames))
    return out_path


def write_if_changed(path, blob):
    if not (path.exists() and path.read_bytes() == blob):
        path.write_bytes(blob)


def resolve_sources(names, src_dir):
    if not names:
        return sorted(src_dir.glob("*.svg"))
    svgs = []
    for n in names:
        p = Path(n)
        if not p.exists():
            p = src_dir / (n if n.endswith(".svg") else n + ".svg")
        if not p.exists():
            sys.exit(f"source not found: {n}")
        svgs.append(p)
    return svgs


def build_icos(names, sizes):
    svgs = resolve_sources(names or list(ICO_STEMS), SRC_DIR)
    ICO_DIR.mkdir(parents=True, exist_ok=True)
    for svg in svgs:
        out = convert_ico(svg, sizes, ICO_DIR)
        print(f"{svg.name} -> {out.relative_to(REPO)}  "
              f"({len(sizes)} sizes: {','.join(map(str, sizes))})")


def build_ce_icos(names):
    """32bpp BMP frames, sizes capped at 32, for CE resource scripts.

    eVC4's rc.exe rejects a PNG-compressed frame (RC2176 "old DIB"), which the
    regular .ico carries at 256."""
    stems = [n for n in names] if names else list(CE_ICO_STEMS)
    ICO_DIR.mkdir(parents=True, exist_ok=True)
    for stem in stems:
        svg = SRC_DIR / f"{stem}.svg"
        if not svg.exists():
            sys.exit(f"source not found: {svg}")
        frames = [(z, render_dib(svg, z, ce_mask=True)) for z in CE_ICO_SIZES]
        out = ICO_DIR / f"{stem}_ce.ico"
        write_if_changed(out, build_ico(frames))
        print(f"{svg.name} -> {out.relative_to(REPO)}  "
              f"({','.join(map(str, CE_ICO_SIZES))})")


def build_ce2_icos(names):
    """4bpp palettised BMP frames, sizes capped at 32."""
    stems = ([n for n in names if n in CE2_ICO_SOURCES] if names
             else list(CE2_ICO_SOURCES))
    ICO_DIR.mkdir(parents=True, exist_ok=True)
    for stem in stems:
        svg = SRC_DIR / f"{CE2_ICO_SOURCES[stem]}.svg"
        if not svg.exists():
            sys.exit(f"source not found: {svg}")
        frames = [(z, render_dib_indexed(svg, z, bpp=CE2_ICO_BPP,
                                         dither=CE2_ICO_DITHER,
                                         palette=WIN16_PALETTE))
                  for z in CE2_ICO_SIZES]
        out = ICO_DIR / f"{stem}_ce2.ico"
        write_if_changed(out, build_ico(frames, bpp=CE2_ICO_BPP))
        print(f"{svg.name} -> {out.relative_to(REPO)}  "
              f"({','.join(map(str, CE2_ICO_SIZES))} @ {CE2_ICO_BPP}bpp)")


def build_logo(names):
    if names and LOGO_ASSET not in {Path(n).stem for n in names}:
        return
    svg = SRC_DIR / f"{LOGO_ASSET}.svg"
    if not svg.exists():
        sys.exit(f"source not found: {svg}")
    ICO_DIR.mkdir(parents=True, exist_ok=True)
    out = ICO_DIR / LOGO_PNG
    write_if_changed(out, render_png(svg, LOGO_PX))
    print(f"{svg.name} -> {out.relative_to(REPO)}  ({LOGO_PX}x{LOGO_PX})")


def build_android_icon(names):
    if names and ANDROID_ICON_STEM not in {Path(n).stem for n in names}:
        return
    svg = SRC_DIR / f"{ANDROID_ICON_STEM}.svg"
    for density, px in ANDROID_ICON_DENSITIES:
        out = ANDROID_RES_DIR / f"mipmap-{density}" / "ic_launcher.png"
        out.parent.mkdir(parents=True, exist_ok=True)
        write_if_changed(out, render_png(svg, px))
        print(f"{svg.name} -> {out.relative_to(REPO)}  ({px}x{px})")


BADGES = [
    ("arm", "ARM", "#0e7c9d"),
    ("mips", "MIPS", "#c0392b"),
]

BADGE_FONT = REPO / "assets" / FONTS_DIR / FONT_SANS_BOLD
FONT_PX = 11
PAD_X = 5
PAD_Y = 3
RADIUS = 2
GAP_X = 4
TEXT_FILL = "#ffffff"


def svg_number(value):
    return f"{value:.2f}".rstrip("0").rstrip(".")


def draw_label(font, text, pen, dx, dy):
    from fontTools.pens.transformPen import TransformPen
    glyphs = font.getGlyphSet()
    cmap = font.getBestCmap()
    scale = FONT_PX / font["head"].unitsPerEm
    x = 0.0
    for ch in text:
        glyph = glyphs[cmap[ord(ch)]]
        glyph.draw(TransformPen(pen, (scale, 0, 0, -scale, dx + x, dy)))
        x += glyph.width * scale


def label_bounds(font, text):
    from fontTools.pens.boundsPen import BoundsPen
    pen = BoundsPen(font.getGlyphSet())
    draw_label(font, text, pen, 0.0, 0.0)
    return pen.bounds


def badge_svg(font, label, fill, box_w, box_h):
    from fontTools.pens.svgPathPen import SVGPathPen
    x_min, y_min, x_max, y_max = label_bounds(font, label)
    pen = SVGPathPen(font.getGlyphSet(), ntos=svg_number)
    draw_label(font, label, pen, (box_w - x_min - x_max) / 2, (box_h - y_min - y_max) / 2)
    width = box_w + GAP_X
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{box_h}" '
            f'viewBox="0 0 {width} {box_h}">'
            f'<rect width="{box_w}" height="{box_h}" rx="{RADIUS}" fill="{fill}"/>'
            f'<path d="{pen.getCommands()}" fill="{TEXT_FILL}"/></svg>\n')


def build_badges():
    from fontTools.ttLib import TTFont
    font = TTFont(BADGE_FONT)
    widest = 0.0
    for _key, label, _fill in BADGES:
        x_min, _y_min, x_max, _y_max = label_bounds(font, label)
        widest = max(widest, x_max - x_min)
    box_w = round(widest) + 2 * PAD_X
    box_h = FONT_PX + 2 * PAD_Y
    for key, label, fill in BADGES:
        out = SRC_DIR / f"{BADGE_PREFIX}{key}.svg"
        write_if_changed(out, badge_svg(font, label, fill, box_w, box_h).encode("utf-8"))
        print(f"{label:5s} -> {out.relative_to(REPO)}  ({box_w + GAP_X}x{box_h})")


def main():
    ap = argparse.ArgumentParser(description="SVG -> CERF icon assets")
    ap.add_argument("names", nargs="*",
                    help=f"source stems or paths (default: every .svg in {ASSET_ICONS_DIR})")
    ap.add_argument("--targets", nargs="+", choices=TARGETS, default=list(TARGETS),
                    help=f"which outputs to build (default: {' '.join(TARGETS)})")
    ap.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)),
                    help="comma-separated pixel sizes for the .ico target")
    args = ap.parse_args()

    try:
        import fontTools  # noqa: F401
        import resvg_py  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError as e:
        sys.exit(f"missing dependency ({e.name}). Run: "
                 f"python -m pip install resvg-py pillow fonttools")

    sizes = [int(x) for x in args.sizes.split(",") if x.strip()]

    if "ico" in args.targets:
        build_icos(args.names, sizes)
    if "ce_ico" in args.targets:
        build_ce_icos([n for n in args.names if n in CE_ICO_STEMS]
                      if args.names else [])
    if "ce2_ico" in args.targets:
        build_ce2_icos(args.names)
    if "logo" in args.targets:
        build_logo(args.names)
    if "android" in args.targets:
        build_android_icon(args.names)
    if "badges" in args.targets and not args.names:
        build_badges()


if __name__ == "__main__":
    main()
