from __future__ import annotations

import math
import tkinter as tk
from typing import Callable, Dict, Optional, Tuple

import antialias as aa

_MARGIN = 2


def _cached(widget: tk.Misc, key: Tuple,
            build: Callable[[tk.Misc], tk.PhotoImage]) -> tk.PhotoImage:
    root = widget._root()
    made: Dict[Tuple, tk.PhotoImage] = root.__dict__.setdefault(
        "_glyph_images", {})
    if key not in made:
        made[key] = build(root)
    return made[key]


def _square(s: float) -> Tuple[int, float]:
    side = 2 * (int(math.ceil(s)) + _MARGIN)
    return side, side / 2.0


def play(widget: tk.Misc, s: float, fill: str,
         outline: Optional[str] = None) -> tk.PhotoImage:
    def build(root: tk.Misc) -> tk.PhotoImage:
        side, c = _square(s)
        sdf = aa.convex_polygon([(c - s * 0.6, c - s), (c - s * 0.6, c + s),
                                 (c + s, c)])
        return aa.render(root, side, side, sdf, fill, outline)
    return _cached(widget, ("play", s, fill, outline), build)


def pause(widget: tk.Misc, s: float, fill: str,
          outline: Optional[str] = None) -> tk.PhotoImage:
    def build(root: tk.Misc) -> tk.PhotoImage:
        side, c = _square(s)
        bw, gap, bh = s * 0.42, s * 0.32, s * 1.7
        sdf = aa.union(aa.box(c - gap - bw, c - bh / 2, c - gap, c + bh / 2),
                       aa.box(c + gap, c - bh / 2, c + gap + bw, c + bh / 2))
        return aa.render(root, side, side, sdf, fill, outline)
    return _cached(widget, ("pause", s, fill, outline), build)


def chevron(widget: tk.Misc, size: int, color: str) -> tk.PhotoImage:
    def build(root: tk.Misc) -> tk.PhotoImage:
        stroke = max(1.0, size / 14.0)
        x0, x1 = size * 0.38, size * 0.66
        y0, y1, y2 = size * 0.19, size * 0.5, size * 0.81
        sdf = aa.union(aa.segment(x0, y0, x1, y1, stroke),
                       aa.segment(x1, y1, x0, y2, stroke))
        return aa.render(root, size, size, sdf, color)
    return _cached(widget, ("chevron", size, color), build)


def info(widget: tk.Misc, size: int, color: str) -> tk.PhotoImage:
    def build(root: tk.Misc) -> tk.PhotoImage:
        c = size / 2.0
        stroke = max(1.0, size / 16.0)
        stem = stroke * 0.55
        sdf = aa.union(
            aa.ring(c, c, c - stroke / 2.0 - 0.5, stroke),
            aa.circle(c, c - size * 0.19, size * 0.065),
            aa.box(c - stem, c - size * 0.06, c + stem, c + size * 0.25))
        return aa.render(root, size, size, sdf, color)
    return _cached(widget, ("info", size, color), build)
