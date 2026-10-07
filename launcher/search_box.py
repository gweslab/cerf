from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

HINT_STYLE = "Hint.TEntry"


class SearchBox:
    def __init__(self, parent: tk.Misc, hint: str,
                 on_change: Callable[[str], None], width: int) -> None:
        self._hint = hint
        self._on_change = on_change
        self._showing_hint = False
        self._var = tk.StringVar(value="")
        self.entry = ttk.Entry(parent, textvariable=self._var, width=width)
        self._var.trace_add("write", self._changed)
        self.entry.bind("<FocusIn>", lambda _e: self._hide_hint())
        self.entry.bind("<FocusOut>", lambda _e: self._show_hint())
        self.entry.bind("<Escape>", self._clear)
        self._show_hint()

    def query(self) -> str:
        return "" if self._showing_hint else self._var.get()

    def focus(self) -> None:
        self.entry.focus_set()
        self.entry.select_range(0, "end")

    def _show_hint(self) -> None:
        if self._showing_hint or self._var.get():
            return
        self._showing_hint = True
        self._var.set(self._hint)
        self.entry.config(style=HINT_STYLE)

    def _hide_hint(self) -> None:
        if not self._showing_hint:
            return
        self._var.set("")
        self._showing_hint = False
        self.entry.config(style="TEntry")

    def _changed(self, *_args: object) -> None:
        if not self._showing_hint:
            self._on_change(self._var.get())

    def _clear(self, _event: object) -> str:
        self._var.set("")
        self.entry.winfo_toplevel().focus_set()
        return "break"
