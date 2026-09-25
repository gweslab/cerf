from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk
from typing import Callable, Optional, Tuple

import ui_theme as theme

HEADING_FONT = ("Segoe UI", 9, "bold")
_GRADIENT_STRENGTH_DARK = 0.12
_GRADIENT_STRENGTH_LIGHT = 1.0
_HEADING_PAD_X = 8
_HEADING_PAD_Y = 4


class SideBlock:
    def __init__(self, parent: tk.Misc, title: str, row: int,
                 warn: bool = False,
                 body_padding: Tuple[int, int, int, int] = (8, 4, 8, 8),
                 on_click: Optional[Callable[[], None]] = None) -> None:
        self._title = title
        self._warn = warn
        self._on_click = on_click
        self._font = tkfont.Font(font=HEADING_FONT)
        self._height = self._font.metrics("linespace") + 2 * _HEADING_PAD_Y

        self.frame = ttk.Frame(parent)
        self.frame.grid(row=row, column=0, sticky="ew")
        self.frame.columnconfigure(0, weight=1)

        self._canvas = tk.Canvas(self.frame, height=self._height, bd=0,
                                 highlightthickness=0, bg=theme.BG)
        self._canvas.grid(row=0, column=0, sticky="ew")
        self._canvas.bind("<Configure>", lambda _e: self._redraw())
        if on_click is not None:
            self._canvas.tag_bind("title", "<Button-1>", lambda _e: on_click())
            self._canvas.tag_bind(
                "title", "<Enter>",
                lambda _e: self._canvas.config(cursor="hand2"))
            self._canvas.tag_bind(
                "title", "<Leave>", lambda _e: self._canvas.config(cursor=""))

        self.body = ttk.Frame(self.frame, padding=body_padding)
        self.body.grid(row=1, column=0, sticky="ew")
        self.body.columnconfigure(0, weight=1)

        self._rule = tk.Frame(self.frame, height=1, bd=0, bg=theme.BORDER)
        self._rule.grid(row=2, column=0, sticky="ew")

    def grid(self) -> None:
        self.frame.grid()

    def grid_remove(self) -> None:
        self.frame.grid_remove()

    def set_title(self, title: str) -> None:
        self._title = title
        self._redraw()

    def retheme(self) -> None:
        self._canvas.config(bg=theme.BG)
        self._rule.config(bg=theme.BORDER)
        self._redraw()

    def _redraw(self) -> None:
        c = self._canvas
        c.delete("all")
        w = c.winfo_width()
        h = self._height
        strength = (_GRADIENT_STRENGTH_DARK if theme.IS_DARK
                    else _GRADIENT_STRENGTH_LIGHT)
        for y in range(h):
            t = strength * (1.0 - y / float(h))
            c.create_line(0, y, w, y, fill=theme.blend(theme.BG, "#ffffff", t))
        if self._on_click is not None:
            fill = theme.LINK_FG
        elif self._warn:
            fill = theme.WARN_FG
        else:
            fill = theme.FG
        c.create_text(_HEADING_PAD_X, h // 2, text=self._title, anchor="w",
                      font=self._font, fill=fill, tags=("title",))
