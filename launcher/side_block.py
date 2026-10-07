from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from branded_dialog import scaled
import glyph_images
from rounded_style import (CARD_MARGIN_X, CONTENT_PADDING, rounded_frame,
                           rounded_style)
from settings_card import ROW_PAD_X_DIP, row_padding
import ui_theme as theme

BLOCK_GAP_DIP = 12
TITLE_GAP_DIP = 6
CHEVRON_DIP = 16


def content_inset(widget: tk.Misc) -> int:
    return 2 * (CARD_MARGIN_X + CONTENT_PADDING
                + scaled(widget, ROW_PAD_X_DIP))


def block_gap(widget: tk.Misc) -> int:
    return scaled(widget, BLOCK_GAP_DIP)


def chevron_reserve(widget: tk.Misc) -> int:
    return scaled(widget, CHEVRON_DIP) + scaled(widget, ROW_PAD_X_DIP)


def _descendants(widget: tk.Misc):
    pending = list(widget.winfo_children())
    while pending:
        child = pending.pop()
        pending.extend(child.winfo_children())
        yield child


class SideBlock:
    def __init__(self, parent: tk.Misc, title: str, row: int,
                 warn: bool = False,
                 on_click: Optional[Callable[[], None]] = None) -> None:
        self.frame = ttk.Frame(parent)
        self.frame.grid(row=row, column=0, sticky="ew", padx=CARD_MARGIN_X,
                        pady=(block_gap(parent), 0))
        self.frame.columnconfigure(0, weight=1)
        ttk.Label(self.frame, text=title,
                  style="Warn.Panel.Section.TLabel" if warn
                  else "Panel.Section.TLabel").grid(row=0, column=0,
                                                    sticky="w")

        self._card = rounded_frame(self.frame, theme.BG_LIGHTER,
                                   theme.CARD_BORDER, theme.BG)
        self._card.grid(row=1, column=0, sticky="ew",
                        pady=(scaled(parent, TITLE_GAP_DIP), 0))
        self._card.columnconfigure(0, weight=1)

        self.body = ttk.Frame(self._card, padding=row_padding(parent))
        self.body.grid(row=0, column=0, sticky="ew")
        self.body.columnconfigure(0, weight=1)

        self._clickable = on_click is not None
        self._hovered = False
        self._tag = "SideBlockCard{}".format(id(self))
        if self._clickable:
            self._chevron = ttk.Label(self._card)
            self._chevron.grid(row=0, column=1,
                               padx=(0, scaled(parent, ROW_PAD_X_DIP)))
            self._card.bind_class(self._tag, "<Enter>",
                                  lambda _e: self._set_hovered(True))
            self._card.bind_class(self._tag, "<Leave>",
                                  lambda _e: self._set_hovered(
                                      self._pointer_inside()))
            self._card.bind_class(self._tag, "<Button-1>",
                                  lambda _e: on_click())
        self.adopt_children()

    def grid(self) -> None:
        self.frame.grid()

    def grid_remove(self) -> None:
        self.frame.grid_remove()

    def adopt_children(self) -> None:
        if self._clickable:
            for widget in [self._card] + list(_descendants(self._card)):
                tags = widget.bindtags()
                if self._tag not in tags:
                    widget.bindtags((self._tag,) + tags)
                    widget.configure(cursor="hand2")
            self._hovered = self._pointer_inside()
        self._restyle()

    def retheme(self) -> None:
        self._restyle()

    def _pointer_inside(self) -> bool:
        card = self._card
        if not card.winfo_ismapped():
            return False
        x, y = card.winfo_pointerxy()
        left, top = card.winfo_rootx(), card.winfo_rooty()
        return (left <= x < left + card.winfo_width()
                and top <= y < top + card.winfo_height())

    def _set_hovered(self, hovered: bool) -> None:
        if hovered != self._hovered:
            self._hovered = hovered
            self._restyle()

    def _restyle(self) -> None:
        fill = theme.CARD_HOVER if self._hovered else theme.BG_LIGHTER
        self._card.configure(style=rounded_style(
            self._card, fill, theme.CARD_BORDER, theme.BG))
        if self._clickable:
            self._chevron.configure(image=glyph_images.chevron(
                self._card, scaled(self._card, CHEVRON_DIP), theme.FG_DIM))
        prefix = (theme.HOVER_STYLE_PREFIX if self._hovered
                  else theme.CARD_STYLE_PREFIX)
        for widget in _descendants(self._card):
            base = str(widget.cget("style")) or widget.winfo_class()
            for known in (theme.HOVER_STYLE_PREFIX, theme.CARD_STYLE_PREFIX):
                if base.startswith(known):
                    base = base[len(known):]
            if base in theme.CARD_STYLE_BASES:
                widget.configure(style=prefix + base)
