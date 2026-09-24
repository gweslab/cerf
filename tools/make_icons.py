#!/usr/bin/env python3
"""Generate every icon asset CERF ships, from one set of SVG sources.

  sources : cerf/assets/icons_sources/*.svg   (authored 16x16, vector-scalable)
  targets :
    ico       cerf/assets/<name>.ico               16/20/24/32/48/64/256, 32-bit alpha
    ce_ico    cerf/assets/<stem>_ce.ico            16/32, 32bpp BMP frames
    ce2_ico   cerf/assets/<stem>_ce2.ico           16/32, 4bpp system-palette frames
              (from the flat *_vga.svg sources, not the gradient ones)
    launcher  launcher/assets/icons/<stem>.png     32x32 RGBA
    wizard    launcher/assets/icons/<stem>.png     64x64 RGBA (New-device wizard pivots)
    toolbar   launcher/assets/icons/<stem>.png     48x48 RGBA (main-window toolbar buttons)
    dialog    launcher/assets/icons/<stem>_<px>.png  branded-dialog icons, per DPI scale
    badges    launcher/assets/icons/badge_<key>.png  CPU-arch badges (no SVG source)
    band      cerf/assets/about_band_<pct>.png     branded-dialog band, per DPI scale
    logo      cerf/assets/cerf_1024.png            app mark, cerf.exe

Each .ico carries every size as its own resvg-rendered frame (vector rendered
natively at each pixel size, not one bitmap downscaled), so small sizes stay
crisp and large sizes stay smooth. CERF loads them per-DPI via
LoadIconWithScaleDown (see HostIconCache).

The launcher renders icons with tk.PhotoImage, which reads PNG but not SVG, and
its two shipped builds run on CPython 3.15 and 3.7-x86 (Vista), for which a
runtime SVG rasterizer has no reliable wheels - so the launcher loads only the
PNGs emitted here. Its stem set is FEATURE_SPECS, built from bundled/db.json.
The README and website reference the SVGs directly and need no target here.

Renderer: resvg (resvg-py) - faithful SVG including filters/gradients, no system
deps. Setup:  python -m pip install resvg-py pillow

Usage:
  python tools/make_icons.py                      # every target
  python tools/make_icons.py --targets ico        # one target (ico|launcher|badges)
  python tools/make_icons.py ga_autoresize        # restrict to these SVG stems
  python tools/make_icons.py --sizes 16,24,32,48,256
"""
import argparse
import sys
from io import BytesIO
from pathlib import Path

from ico_format import (WIN16_PALETTE, build_ico, dib_frame,
                        dib_frame_indexed)

DEFAULT_SIZES = [16, 20, 24, 32, 48, 64, 256]
LAUNCHER_SIZE = 32  # rendered 1:1 at the side-panel display size
WIZARD_SIZE = 64    # New-device wizard pivot buttons
WIZARD_STEMS = ("local_rom", "download")
TOOLBAR_SIZE = 48
TOOLBAR_STEMS = ("new_device", "start_device", "refresh_remote",
                 "update_from_remote", "delete_device", "discard_state",
                 "help", "settings", "feedback", "wrench")
DIALOG_SIZES = (32, 40, 48, 64, 96)
DIALOG_STEMS = ("cerf_error", "cerf", "cerf_setup")
LAUNCHER_ONLY_STEMS = WIZARD_STEMS + TOOLBAR_STEMS

REPO = Path(__file__).resolve().parent.parent
SRC_DIR = REPO / "cerf" / "assets" / "icons_sources"
ICO_DIR = REPO / "cerf" / "assets"
LAUNCHER_DIR = REPO / "launcher" / "assets" / "icons"

CE_ICO_STEMS = ("cerf",)
CE_ICO_SIZES = (16, 32)

CE2_ICO_SOURCES = {"cerf": "cerf_vga"}   # output stem -> svg stem
CE_ONLY_STEMS = ("cerf_vga",)
CE2_ICO_SIZES = (16, 32)
CE2_ICO_BPP = 4
CE2_ICO_DITHER = False

BAND_STEM = "about_band"
BAND_SCALES = (100, 125, 150, 200, 300)

LOGO_STEM = "cerf"
LOGO_PX = 1024

TARGETS = ("ico", "ce_ico", "ce2_ico", "launcher", "wizard", "toolbar",
           "dialog", "badges", "band", "logo")


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


UNSUP_DIM_ALPHA = 0.73
UNSUP_BADGE_FRAC = 0.42
UNSUP_RED = (229, 72, 77)
UNSUP_WHITE = (255, 255, 255)


def make_unsupported_variant(base):
    """base RGBA PIL Image -> a dimmed copy with a bottom-right error badge."""
    from PIL import Image, ImageDraw
    size = base.width
    out = base.copy()
    out.putalpha(out.getchannel("A").point(lambda a: int(a * UNSUP_DIM_ALPHA)))

    d = max(1, round(size * UNSUP_BADGE_FRAC))
    big = Image.new("RGBA", (d * SS, d * SS), (0, 0, 0, 0))
    draw = ImageDraw.Draw(big)
    hi = d * SS - 1
    ring = max(1, round(d * SS * 0.08))
    draw.ellipse([0, 0, hi, hi], fill=UNSUP_WHITE + (255,))
    draw.ellipse([ring, ring, hi - ring, hi - ring], fill=UNSUP_RED + (255,))
    inset = d * SS * 0.30
    stroke = max(1, round(d * SS * 0.14))
    draw.line([inset, inset, hi - inset, hi - inset],
              fill=UNSUP_WHITE + (255,), width=stroke)
    draw.line([hi - inset, inset, inset, hi - inset],
              fill=UNSUP_WHITE + (255,), width=stroke)
    badge = big.resize((d, d), Image.LANCZOS)
    out.alpha_composite(badge, (size - d, size - d))
    return out


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


def launcher_stems():
    sys.path.insert(0, str(REPO / "launcher"))
    from board_database import FEATURE_SPECS
    return sorted({stem for _key, stem, _label in FEATURE_SPECS})


# ---------------------------------------------------------------- targets

def build_icos(names, sizes):
    svgs = resolve_sources(names, SRC_DIR)
    svgs = [s for s in svgs if s.stem != BAND_STEM]
    if not names:
        skip = set(LAUNCHER_ONLY_STEMS) | set(CE_ONLY_STEMS)
        svgs = [s for s in svgs if s.stem not in skip]
    if not svgs:
        sys.exit(f"no .svg sources in {SRC_DIR}")
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


def svg_intrinsic(svg_path):
    import re
    t = svg_path.read_text(encoding="utf-8")
    w = re.search(r'<svg[^>]*\bwidth="(\d+)"', t)
    h = re.search(r'<svg[^>]*\bheight="(\d+)"', t)
    if w and h:
        return int(w.group(1)), int(h.group(1))
    vb = re.search(r'viewBox="[\d.]+ [\d.]+ ([\d.]+) ([\d.]+)"', t)
    if vb:
        return round(float(vb.group(1))), round(float(vb.group(2)))
    sys.exit(f"cannot determine intrinsic size: {svg_path}")


def render_png_wh(svg_path, w, h):
    import resvg_py
    from PIL import Image
    raw = resvg_py.svg_to_bytes(svg_path=str(svg_path), width=w, height=h)
    im = Image.open(BytesIO(bytes(raw))).convert("RGBA")
    if im.size != (w, h):
        im = im.resize((w, h), Image.LANCZOS)
    buf = BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()


def build_band(names):
    if names and BAND_STEM not in {Path(n).stem for n in names}:
        return
    svg = SRC_DIR / f"{BAND_STEM}.svg"
    if not svg.exists():
        sys.exit(f"source not found: {svg}")
    w0, h0 = svg_intrinsic(svg)
    ICO_DIR.mkdir(parents=True, exist_ok=True)
    for pct in BAND_SCALES:
        w, h = round(w0 * pct / 100), round(h0 * pct / 100)
        out = ICO_DIR / f"{BAND_STEM}_{pct}.png"
        write_if_changed(out, render_png_wh(svg, w, h))
        print(f"{svg.name} -> {out.relative_to(REPO)}  ({w}x{h})")


def build_logo(names):
    """One large square PNG of the app mark.

    Stays a raster: Tk's PhotoImage reads PNG but not SVG, and the launcher's
    two shipped builds have no runtime SVG rasterizer."""
    if names and LOGO_STEM not in {Path(n).stem for n in names}:
        return
    svg = SRC_DIR / f"{LOGO_STEM}.svg"
    if not svg.exists():
        sys.exit(f"source not found: {svg}")
    ICO_DIR.mkdir(parents=True, exist_ok=True)
    out = ICO_DIR / f"{LOGO_STEM}_{LOGO_PX}.png"
    write_if_changed(out, render_png(svg, LOGO_PX))
    print(f"{svg.name} -> {out.relative_to(REPO)}  ({LOGO_PX}x{LOGO_PX})")


def build_launcher_pngs(names):
    stems = launcher_stems()
    if names:
        wanted = {Path(n).stem for n in names}
        stems = [s for s in stems if s in wanted]
    LAUNCHER_DIR.mkdir(parents=True, exist_ok=True)
    for stem in stems:
        svg = SRC_DIR / f"{stem}.svg"
        if not svg.exists():
            sys.exit(f"source not found: {svg}")
        base = render_image(svg, LAUNCHER_SIZE)
        buf = BytesIO()
        base.save(buf, format="PNG")
        out = LAUNCHER_DIR / f"{stem}.png"
        write_if_changed(out, buf.getvalue())
        buf = BytesIO()
        make_unsupported_variant(base).save(buf, format="PNG")
        out_u = LAUNCHER_DIR / f"{stem}_unsupported.png"
        write_if_changed(out_u, buf.getvalue())
        print(f"{svg.name} -> {out.relative_to(REPO)}, "
              f"{out_u.name}  ({LAUNCHER_SIZE}x{LAUNCHER_SIZE})")


def build_wizard_pngs(names):
    stems = list(WIZARD_STEMS)
    if names:
        wanted = {Path(n).stem for n in names}
        stems = [s for s in stems if s in wanted]
    LAUNCHER_DIR.mkdir(parents=True, exist_ok=True)
    for stem in stems:
        svg = SRC_DIR / f"{stem}.svg"
        if not svg.exists():
            sys.exit(f"source not found: {svg}")
        out = LAUNCHER_DIR / f"{stem}.png"
        write_if_changed(out, render_png(svg, WIZARD_SIZE))
        print(f"{svg.name} -> {out.relative_to(REPO)}  "
              f"({WIZARD_SIZE}x{WIZARD_SIZE})")


def build_dialog_pngs(names):
    stems = list(DIALOG_STEMS)
    if names:
        wanted = {Path(n).stem for n in names}
        stems = [s for s in stems if s in wanted]
    LAUNCHER_DIR.mkdir(parents=True, exist_ok=True)
    for stem in stems:
        svg = SRC_DIR / f"{stem}.svg"
        if not svg.exists():
            sys.exit(f"source not found: {svg}")
        for px in DIALOG_SIZES:
            out = LAUNCHER_DIR / f"{stem}_{px}.png"
            write_if_changed(out, render_png(svg, px))
        print(f"{svg.name} -> {LAUNCHER_DIR.relative_to(REPO)}/{stem}_<px>.png  "
              f"({','.join(map(str, DIALOG_SIZES))})")


def build_toolbar_pngs(names):
    stems = list(TOOLBAR_STEMS)
    if names:
        wanted = {Path(n).stem for n in names}
        stems = [s for s in stems if s in wanted]
    LAUNCHER_DIR.mkdir(parents=True, exist_ok=True)
    for stem in stems:
        svg = SRC_DIR / f"{stem}.svg"
        if not svg.exists():
            sys.exit(f"source not found: {svg}")
        out = LAUNCHER_DIR / f"{stem}.png"
        write_if_changed(out, render_png(svg, TOOLBAR_SIZE))
        print(f"{svg.name} -> {out.relative_to(REPO)}  "
              f"({TOOLBAR_SIZE}x{TOOLBAR_SIZE})")


# Badges have no SVG source: they are text-in-a-box, sized to the widest label.
# (filename key, label, background RGB). White text on each.
BADGES = [
    ("arm", "ARM", (14, 124, 157)),    # ARM brand teal
    ("mips", "MIPS", (192, 57, 43)),   # MIPS brand red
]

SS = 4              # supersampling factor
FONT_PX = 11        # display-pixel font size
PAD_X = 5           # display-pixel horizontal padding inside the box
PAD_Y = 3           # display-pixel vertical padding inside the box
RADIUS = 2          # display-pixel corner radius
GAP_X = 4           # transparent margin after the box so following text
                    # (table cell / Label / README) isn't flush against it
TEXT_RGB = (255, 255, 255)

# Bold sans-serif candidates, most-preferred first; falls back to DejaVu.
BOLD_FONT_CANDIDATES = [
    "arialbd.ttf", "segoeuib.ttf", "DejaVuSans-Bold.ttf",
    "Arial Bold.ttf", "LiberationSans-Bold.ttf",
]


def load_font(px):
    from PIL import ImageFont
    for name in BOLD_FONT_CANDIDATES:
        try:
            return ImageFont.truetype(name, px)
        except OSError:
            continue
    return ImageFont.load_default(size=px)


def text_size(font, text):
    l, t, r, b = font.getbbox(text)
    return r - l, b - t


def render_badge(label, bg, box_w, box_h, font):
    """Render one badge at supersampled scale, return a (box_w + GAP_X, box_h)
    RGBA: the coloured box on the left, then a transparent right margin so text
    placed after the badge keeps a gap.

    Supersampled then downsampled (LANCZOS) so the rounded corners and text stay
    crisp at the small display size."""
    from PIL import Image, ImageDraw
    big = Image.new("RGBA", (box_w * SS, box_h * SS), (0, 0, 0, 0))
    draw = ImageDraw.Draw(big)
    draw.rounded_rectangle(
        [0, 0, box_w * SS - 1, box_h * SS - 1],
        radius=RADIUS * SS, fill=bg + (255,))
    # Centre by the glyph bbox (anchor="mm" centres on the text's own box).
    draw.text((box_w * SS / 2, box_h * SS / 2), label, font=font,
              fill=TEXT_RGB + (255,), anchor="mm")
    badge = big.resize((box_w, box_h), Image.LANCZOS)
    out = Image.new("RGBA", (box_w + GAP_X, box_h), (0, 0, 0, 0))
    out.paste(badge, (0, 0))
    return out


def build_badges():
    font_big = load_font(FONT_PX * SS)
    # One shared box, sized to the widest label so all badges match.
    widest = max(text_size(font_big, label)[0] / SS for _, label, _ in BADGES)
    box_w = round(widest) + 2 * PAD_X
    box_h = FONT_PX + 2 * PAD_Y

    LAUNCHER_DIR.mkdir(parents=True, exist_ok=True)
    for key, label, bg in BADGES:
        img = render_badge(label, bg, box_w, box_h, font_big)
        out = LAUNCHER_DIR / f"badge_{key}.png"
        buf = BytesIO()
        img.save(buf, format="PNG")
        write_if_changed(out, buf.getvalue())
        print(f"{label:5s} -> {out.relative_to(REPO)}  ({img.width}x{img.height})")


def main():
    ap = argparse.ArgumentParser(description="SVG -> CERF icon assets")
    ap.add_argument("names", nargs="*",
                    help="source stems or paths (default: every .svg in icons_sources)")
    ap.add_argument("--targets", nargs="+", choices=TARGETS, default=list(TARGETS),
                    help=f"which outputs to build (default: {' '.join(TARGETS)})")
    ap.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)),
                    help="comma-separated pixel sizes for the .ico target")
    args = ap.parse_args()

    try:
        import resvg_py  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError as e:
        sys.exit(f"missing dependency ({e.name}). Run: "
                 f"python -m pip install resvg-py pillow")

    sizes = [int(x) for x in args.sizes.split(",") if x.strip()]

    if "ico" in args.targets:
        build_icos(args.names, sizes)
    if "ce_ico" in args.targets:
        build_ce_icos([n for n in args.names if n in CE_ICO_STEMS]
                      if args.names else [])
    if "ce2_ico" in args.targets:
        build_ce2_icos(args.names)
    if "launcher" in args.targets:
        build_launcher_pngs(args.names)
    if "wizard" in args.targets:
        build_wizard_pngs(args.names)
    if "toolbar" in args.targets:
        build_toolbar_pngs(args.names)
    if "dialog" in args.targets:
        build_dialog_pngs(args.names)
    if "band" in args.targets:
        build_band(args.names)
    if "logo" in args.targets:
        build_logo(args.names)
    if "badges" in args.targets and not args.names:
        build_badges()


if __name__ == "__main__":
    main()
