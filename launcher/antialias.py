from __future__ import annotations

import base64
import math
import struct
import tkinter as tk
import zlib
from typing import Callable, Optional, Sequence, Tuple

SUPERSAMPLE = 4
_SURE = 0.75

Sdf = Callable[[float, float], float]
Point = Tuple[float, float]


def coverage(sdf: Sdf, x: int, y: int) -> float:
    centre = sdf(x + 0.5, y + 0.5)
    if centre >= _SURE:
        return 1.0
    if centre < -_SURE:
        return 0.0
    hits = 0
    for sy in range(SUPERSAMPLE):
        py = y + (sy + 0.5) / SUPERSAMPLE
        for sx in range(SUPERSAMPLE):
            if sdf(x + (sx + 0.5) / SUPERSAMPLE, py) >= 0.0:
                hits += 1
    return hits / float(SUPERSAMPLE * SUPERSAMPLE)


def rounded_box(x0: float, y0: float, x1: float, y1: float,
                radius: float) -> Sdf:
    def sdf(px: float, py: float) -> float:
        dx = max(x0 + radius - px, 0.0, px - (x1 - radius))
        dy = max(y0 + radius - py, 0.0, py - (y1 - radius))
        return radius - math.hypot(dx, dy)
    return sdf


def box(x0: float, y0: float, x1: float, y1: float) -> Sdf:
    return lambda px, py: min(px - x0, x1 - px, py - y0, y1 - py)


def circle(cx: float, cy: float, radius: float) -> Sdf:
    return lambda px, py: radius - math.hypot(px - cx, py - cy)


def ring(cx: float, cy: float, radius: float, stroke: float) -> Sdf:
    half = stroke / 2.0
    return lambda px, py: half - abs(radius - math.hypot(px - cx, py - cy))


def segment(ax: float, ay: float, bx: float, by: float,
            stroke: float) -> Sdf:
    half = stroke / 2.0
    dx, dy = bx - ax, by - ay
    length2 = dx * dx + dy * dy

    def sdf(px: float, py: float) -> float:
        t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / length2))
        return half - math.hypot(px - ax - t * dx, py - ay - t * dy)
    return sdf


def convex_polygon(points: Sequence[Point]) -> Sdf:
    area = sum(points[i][0] * points[i - 1][1] - points[i - 1][0] * points[i][1]
               for i in range(len(points)))
    sign = 1.0 if area > 0 else -1.0
    edges = []
    for i in range(len(points)):
        (ax, ay), (bx, by) = points[i - 1], points[i]
        length = math.hypot(bx - ax, by - ay)
        edges.append((ax, ay, sign * (by - ay) / length,
                      sign * (ax - bx) / length))

    def sdf(px: float, py: float) -> float:
        return min((px - ax) * nx + (py - ay) * ny for ax, ay, nx, ny in edges)
    return sdf


def union(*parts: Sdf) -> Sdf:
    return lambda px, py: max(part(px, py) for part in parts)


def _rgb(color: str) -> Tuple[int, int, int]:
    return (int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16))


def _png(width: int, height: int, rows: Sequence[bytes]) -> bytes:
    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + tag + payload
                + struct.pack(">I", zlib.crc32(tag + payload) & 0xffffffff))
    raw = b"".join(b"\x00" + row for row in rows)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6,
                                         0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def render(root: tk.Misc, width: int, height: int, sdf: Sdf, fill: str,
           outline: Optional[str] = None,
           outline_width: float = 1.0) -> tk.PhotoImage:
    fill_c = _rgb(fill)
    edge_c = _rgb(outline) if outline else fill_c
    body_sdf = (lambda px, py: sdf(px, py) - outline_width) if outline else sdf
    rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            shape = coverage(sdf, x, y)
            if shape <= 0.0:
                row += b"\x00\x00\x00\x00"
                continue
            body = coverage(body_sdf, x, y) if outline else shape
            row += bytes(int(round((edge_c[i] * (shape - body)
                                    + fill_c[i] * body) / shape))
                         for i in range(3))
            row.append(int(round(255 * shape)))
        rows.append(bytes(row))
    data = base64.b64encode(_png(width, height, rows)).decode("ascii")
    return tk.PhotoImage(master=root, data=data, format="png")
