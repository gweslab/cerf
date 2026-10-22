"""Vertically scrollable column: a Canvas-hosted inner frame with a
scrollbar, width-follow, and recursive mouse-wheel binding."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from sv_elements import PAGE_SCROLLBAR_STYLE, THIN_SCROLLBAR_STYLE
import ui_theme as theme

WHEEL_NOTCH_DELTA = 120


def fit_scrollregion(canvas: tk.Canvas, pad_bottom: int = 0) -> None:
    box = canvas.bbox("all")
    width = box[2] if box else 0
    height = max(box[3] + pad_bottom if box else 0, canvas.winfo_height())
    canvas.configure(scrollregion=(0, 0, width, height))


def _scroll_pixels(canvas: tk.Canvas, delta_y: int) -> None:
    region = canvas.cget("scrollregion").split()
    total = float(region[3]) - float(region[1]) if len(region) == 4 else 0.0
    if total <= 0.0:
        return
    top = canvas.yview()[0] * total
    canvas.yview_moveto((top - delta_y) / total)


def _touchpad_delta_y(packed: int) -> int:
    low = packed & 0xFFFF
    return low - 0x10000 if low >= 0x8000 else low


def bind_wheel_scroll(widget: tk.Misc, canvas: tk.Canvas) -> None:
    def units(count: int) -> str:
        canvas.yview_scroll(count, "units")
        return "break"

    def pixels(packed: int) -> str:
        _scroll_pixels(canvas, _touchpad_delta_y(packed))
        return "break"

    widget.bind("<MouseWheel>", lambda e: units(int(-e.delta / WHEEL_NOTCH_DELTA)))
    widget.bind("<Button-4>", lambda _e: units(-1))
    widget.bind("<Button-5>", lambda _e: units(1))
    if float(widget.tk.call("info", "patchlevel").rsplit(".", 1)[0]) >= 9.0:
        widget.bind("<TouchpadScroll>", lambda e: pixels(e.delta))


class ScrollColumn:
    """A fixed-width, vertically scrollable content column. Build content
    into `.inner`; call `bind_wheel(widget)` after adding dynamic children
    so the mouse wheel keeps scrolling over them."""

    def __init__(self, parent: tk.Misc, width: int,
                 on_width_changed: Optional[Callable[[int], None]] = None,
                 page: bool = False, pad_bottom: int = 0):
        self._page = page
        self._canvas = tk.Canvas(parent, bg=self._background(),
                                 highlightthickness=0, width=width)
        self.scrollbar = ttk.Scrollbar(
            parent, orient="vertical", command=self._canvas.yview,
            style=PAGE_SCROLLBAR_STYLE if page else THIN_SCROLLBAR_STYLE)
        self._canvas.configure(yscrollcommand=self.scrollbar.set)

        self.inner = ttk.Frame(self._canvas,
                               style="Page.TFrame" if page else "TFrame",
                               padding=(0, 0, 0, pad_bottom))
        self._inner_id = self._canvas.create_window((0, 0), window=self.inner,
                                                    anchor="nw")
        self.inner.columnconfigure(0, weight=1)

        self.inner.bind("<Configure>",
                        lambda _e: fit_scrollregion(self._canvas))

        def _follow_canvas_width(width: int) -> None:
            self._canvas.itemconfigure(self._inner_id, width=width)
            fit_scrollregion(self._canvas)
            if on_width_changed is not None:
                on_width_changed(width)

        def _on_canvas_config(e: object) -> None:
            if self._canvas.winfo_toplevel().winfo_ismapped():
                _follow_canvas_width(e.width)
        self._canvas.bind("<Configure>", _on_canvas_config)
        self._canvas.bind(
            "<Map>", lambda _e: _follow_canvas_width(self._canvas.winfo_width()))

        self.bind_wheel(self._canvas)
        self.bind_wheel(self.inner)

    @property
    def canvas(self) -> tk.Canvas:
        return self._canvas

    def _background(self) -> str:
        return theme.PAGE_BG if self._page else theme.BG

    def retheme(self) -> None:
        self._canvas.config(bg=self._background())

    def set_width(self, width: int) -> None:
        self._canvas.config(width=width)

    def scroll_to_top(self) -> None:
        self._canvas.yview_moveto(0.0)

    def grid(self, row: int, column: int, **kwargs) -> None:
        self._canvas.grid(row=row, column=column, **kwargs)
        self.scrollbar.grid(row=row, column=column + 1, sticky="ns")

    def bind_wheel(self, widget: tk.Misc) -> None:
        bind_wheel_scroll(widget, self._canvas)
        for child in widget.winfo_children():
            self.bind_wheel(child)
