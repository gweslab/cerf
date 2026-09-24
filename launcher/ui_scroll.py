"""Vertically scrollable column: a Canvas-hosted inner frame with a
scrollbar, width-follow, and recursive mouse-wheel binding."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

import ui_theme as theme


def fit_scrollregion(canvas: tk.Canvas) -> None:
    box = canvas.bbox("all")
    width = box[2] if box else 0
    height = max(box[3] if box else 0, canvas.winfo_height())
    canvas.configure(scrollregion=(0, 0, width, height))


class ScrollColumn:
    """A fixed-width, vertically scrollable content column. Build content
    into `.inner`; call `bind_wheel(widget)` after adding dynamic children
    so the mouse wheel keeps scrolling over them."""

    def __init__(self, parent: tk.Misc, width: int,
                 on_width_changed: Optional[Callable[[int], None]] = None):
        self._canvas = tk.Canvas(parent, bg=theme.BG, highlightthickness=0,
                                 width=width)
        self.scrollbar = ttk.Scrollbar(parent, orient="vertical",
                                       command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self.scrollbar.set)

        self.inner = ttk.Frame(self._canvas)
        self._inner_id = self._canvas.create_window((0, 0), window=self.inner,
                                                    anchor="nw")
        self.inner.columnconfigure(0, weight=1)

        self.inner.bind("<Configure>",
                        lambda _e: fit_scrollregion(self._canvas))

        def _on_canvas_config(e: object) -> None:
            self._canvas.itemconfigure(self._inner_id, width=e.width)
            fit_scrollregion(self._canvas)
            if on_width_changed is not None:
                on_width_changed(e.width)
        self._canvas.bind("<Configure>", _on_canvas_config)

        self.bind_wheel(self._canvas)
        self.bind_wheel(self.inner)

    def retheme(self) -> None:
        self._canvas.config(bg=theme.BG)

    def grid(self, row: int, column: int, **kwargs) -> None:
        self._canvas.grid(row=row, column=column, **kwargs)
        self.scrollbar.grid(row=row, column=column + 1, sticky="ns")

    def _on_wheel(self, event: object) -> str:
        self._canvas.yview_scroll(int(-event.delta / 120), "units")
        return "break"

    def bind_wheel(self, widget: tk.Misc) -> None:
        widget.bind("<MouseWheel>", self._on_wheel)
        for child in widget.winfo_children():
            self.bind_wheel(child)
