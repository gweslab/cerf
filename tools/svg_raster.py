import re
import sys
from io import BytesIO


def intrinsic_size(svg_text):
    w = re.search(r'<svg[^>]*\bwidth="(\d+)"', svg_text)
    h = re.search(r'<svg[^>]*\bheight="(\d+)"', svg_text)
    if not (w and h):
        vb = re.search(r'viewBox="[\d.]+ [\d.]+ ([\d.]+) ([\d.]+)"', svg_text)
        if not vb:
            sys.exit("cannot determine SVG intrinsic size")
        return round(float(vb.group(1))), round(float(vb.group(2)))
    return int(w.group(1)), int(h.group(1))


def render_svg(svg_path, width, height, mode):
    import resvg_py
    from PIL import Image
    raw = resvg_py.svg_to_bytes(svg_path=str(svg_path), width=width, height=height)
    img = Image.open(BytesIO(bytes(raw))).convert(mode)
    if img.size != (width, height):
        img = img.resize((width, height), Image.LANCZOS)
    return img
