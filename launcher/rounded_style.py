from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Tuple

RADIUS = 5
SUPERSAMPLE = 4
CONTENT_PADDING = 3
STRETCH_CENTER = 64

Rgb = Tuple[float, float, float]


def _rgb(color: str) -> Rgb:
    return (int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16))


def _inside(px: float, py: float, x0: float, y0: float, x1: float, y1: float,
            radius: float) -> bool:
    dx = max(x0 + radius - px, 0.0, px - (x1 - radius))
    dy = max(y0 + radius - py, 0.0, py - (y1 - radius))
    return dx * dx + dy * dy <= radius * radius


def _coverage(x: int, y: int, size: int, inset: float, radius: float) -> float:
    hits = 0
    for sy in range(SUPERSAMPLE):
        for sx in range(SUPERSAMPLE):
            px = x + (sx + 0.5) / SUPERSAMPLE
            py = y + (sy + 0.5) / SUPERSAMPLE
            if _inside(px, py, inset, inset, size - inset, size - inset,
                       radius):
                hits += 1
    return hits / float(SUPERSAMPLE * SUPERSAMPLE)


def _mix(parts: List[Tuple[Rgb, float]]) -> str:
    r = sum(c[0] * w for c, w in parts)
    g = sum(c[1] * w for c, w in parts)
    b = sum(c[2] * w for c, w in parts)
    return "#{:02x}{:02x}{:02x}".format(int(round(r)), int(round(g)),
                                         int(round(b)))


def _corner_tile(fill: str, border: str, outer: str) -> List[List[str]]:
    size = 2 * (RADIUS + 1) + 1
    fill_c, border_c, outer_c = _rgb(fill), _rgb(border), _rgb(outer)
    tile = []
    for y in range(size):
        row = []
        for x in range(size):
            shape = _coverage(x, y, size, 0.0, RADIUS)
            body = _coverage(x, y, size, 1.0, RADIUS - 1)
            row.append(_mix([(outer_c, 1.0 - shape),
                             (border_c, shape - body),
                             (fill_c, body)]))
        tile.append(row)
    return tile


def _stretch_index(i: int, size: int) -> int:
    edge = RADIUS + 1
    if i <= edge:
        return i
    if i >= size - edge:
        return i - (size - (2 * edge + 1))
    return edge


def _render(root: tk.Misc, fill: str, border: str,
            outer: str) -> tk.PhotoImage:
    tile = _corner_tile(fill, border, outer)
    size = 2 * (RADIUS + 1) + STRETCH_CENTER
    rows = []
    for y in range(size):
        src = tile[_stretch_index(y, size)]
        rows.append("{" + " ".join(src[_stretch_index(x, size)]
                                   for x in range(size)) + "}")
    image = tk.PhotoImage(master=root, width=size, height=size)
    image.put(" ".join(rows))
    return image


def rounded_style(widget: tk.Misc, fill: str, border: str, outer: str) -> str:
    root = widget.winfo_toplevel()._root()
    theme_name = str(root.tk.call("ttk::style", "theme", "use"))
    key = "Rounded_{}_{}_{}".format(fill[1:], border[1:], outer[1:])
    made: Dict[Tuple[str, str], tk.PhotoImage] = root.__dict__.setdefault(
        "_rounded_style_images", {})
    style_name = key + ".TFrame"
    if (theme_name, key) not in made:
        image = _render(root, fill, border, outer)
        made[(theme_name, key)] = image
        style = ttk.Style(root)
        element = key + ".field"
        style.element_create(element, "image", image, border=RADIUS + 1,
                             sticky="nsew")
        style.layout(style_name, [(element, {"sticky": "nswe"})])
    return style_name


def rounded_frame(parent: tk.Misc, fill: str, border: str, outer: str,
                  **options) -> ttk.Frame:
    return ttk.Frame(parent, style=rounded_style(parent, fill, border, outer),
                     padding=CONTENT_PADDING, **options)
