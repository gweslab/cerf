from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import Optional, Tuple

from device_state import DeviceBundle
from preview_tile import PreviewTile
from rounded_style import CONTENT_PADDING, rounded_corners
import ui_theme as theme

HEADING_FONT = ("Segoe UI", 11, "bold")
DETAIL_FONT = ("Segoe UI", 9)
CARD_MARGIN_X = 2
TILE_PAD_X = 4
TILE_PAD_Y = 3
TEXT_PAD_X = 6
TEXT_PAD_Y = 2
BADGE_GAP = 2
CORNER_ANCHORS = ("nw", "ne", "sw", "se")


class DeviceCard:
    def __init__(self, canvas: tk.Canvas, tag: str, device: DeviceBundle,
                 collide: bool, devices_dir: Path, tile_size: Tuple[int, int],
                 glyph: int, line_height: int) -> None:
        self.canvas = canvas
        self.tag = tag
        self.device = device
        self.collide = collide
        self.top = 0
        self.bottom = 0
        self._tile_w, self._tile_h = tile_size
        self._line_h = line_height
        self._tile_box = (0, 0, 0, 0)
        self._painted: Optional[Tuple[str, str]] = None
        self._badge_image: Optional[tk.PhotoImage] = None
        c, tags = canvas, (tag,)
        self._bg = c.create_rectangle(0, 0, 0, 0, width=1, tags=tags)
        self._corners = [c.create_image(0, 0, anchor=a, tags=tags)
                         for a in CORNER_ANCHORS]
        self._heading = c.create_text(0, 0, anchor="nw", font=HEADING_FONT,
                                      fill=theme.FG, tags=tags)
        self._prefix = self._detail_text(tags)
        self._badge = c.create_image(0, 0, anchor="nw", tags=tags)
        self._soc = self._detail_text(tags)
        self._suffix = self._detail_text(tags)
        self._status = self._detail_text(tags)
        self.tile = PreviewTile.on_canvas(canvas, tag + ".tile", devices_dir,
                                          self._tile_w, self._tile_h, glyph)

    def _detail_text(self, tags: Tuple[str, ...]) -> int:
        return self.canvas.create_text(0, 0, anchor="nw", font=DETAIL_FONT,
                                       fill=theme.FG_DIM, tags=tags)

    def _set_text(self, item: int, text: str) -> bool:
        if self.canvas.itemcget(item, "text") == text:
            return False
        self.canvas.itemconfigure(item, text=text)
        return True

    def set_texts(self, heading: str, prefix: str, soc: str,
                  suffix: str) -> bool:
        changed = self._set_text(self._heading, heading)
        changed |= self._set_text(self._prefix, prefix)
        changed |= self._set_text(self._soc, soc)
        changed |= self._set_text(self._suffix, suffix)
        return changed

    def set_status(self, text: str, color: str) -> None:
        if self._set_text(self._status, text):
            self.canvas.itemconfigure(self._status, fill=color)

    def set_badge(self, image: Optional[tk.PhotoImage]) -> None:
        self._badge_image = image
        self.canvas.itemconfigure(self._badge, image=image or "")

    def _place_text(self, item: int, x: int, y: int) -> int:
        self.canvas.coords(item, x, y)
        if not self.canvas.itemcget(item, "text"):
            return x
        return self.canvas.bbox(item)[2]

    def layout(self, y: int, width: int, wrap: int) -> int:
        c = self.canvas
        x0 = CARD_MARGIN_X
        x1 = width - CARD_MARGIN_X - 1
        tx = x0 + CONTENT_PADDING + TILE_PAD_X
        ty = y + CONTENT_PADDING + TILE_PAD_Y
        self.tile.move_to(tx, ty)
        self._tile_box = (tx, ty, tx + self._tile_w, ty + self._tile_h)

        text_x = tx + self._tile_w + TILE_PAD_X + TEXT_PAD_X
        text_y = y + CONTENT_PADDING + TEXT_PAD_Y
        c.itemconfigure(self._heading, width=wrap)
        c.coords(self._heading, text_x, text_y)
        box = c.bbox(self._heading)
        line_y = text_y + (box[3] - box[1] if box else self._line_h)

        x = self._place_text(self._prefix, text_x, line_y)
        if self._badge_image is not None:
            c.coords(self._badge, x, line_y
                     + (self._line_h - self._badge_image.height()) // 2)
            x += self._badge_image.width() + BADGE_GAP
        x = self._place_text(self._soc, x, line_y)
        self._place_text(self._suffix, x, line_y)
        c.coords(self._status, text_x, line_y + self._line_h)

        y1 = max(line_y + 2 * self._line_h + TEXT_PAD_Y + CONTENT_PADDING,
                 ty + self._tile_h + TILE_PAD_Y + CONTENT_PADDING)
        c.coords(self._bg, x0, y, x1, y1)
        for item, (cx, cy) in zip(self._corners, ((x0, y), (x1 + 1, y),
                                                  (x0, y1 + 1),
                                                  (x1 + 1, y1 + 1))):
            c.coords(item, cx, cy)
        self.top, self.bottom = y, y1
        return y1 + 1

    def paint(self, fill: str, border: str) -> None:
        if self._painted == (fill, border):
            return
        self._painted = (fill, border)
        c = self.canvas
        c.itemconfigure(self._bg, fill=fill, outline=border)
        for item, image in zip(self._corners,
                               rounded_corners(c, fill, border, theme.BG)):
            c.itemconfigure(item, image=image)

    def hit(self, x: float, y: float) -> Optional[str]:
        if not self.top <= y <= self.bottom:
            return None
        bx0, by0, bx1, by1 = self._tile_box
        if bx0 <= x < bx1 and by0 <= y < by1:
            return "tile"
        return "card"

    def delete(self) -> None:
        self.tile.delete()
        self.canvas.delete(self.tag)
