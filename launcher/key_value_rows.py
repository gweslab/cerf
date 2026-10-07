from __future__ import annotations

import tkinter.font as tkfont
from tkinter import ttk
from typing import List, Optional, Sequence, Tuple

KEY_GAP = 12
STACK_GAP = 4
SPLIT_GROUP = "split"

Rows = Sequence[Tuple[str, str]]


class KeyValueRows:
    def __init__(self, body: ttk.Frame) -> None:
        self._body = body
        for column in (0, 1):
            body.columnconfigure(column, weight=1, uniform=SPLIT_GROUP)
        self._texts: List[Tuple[str, str]] = []
        self._labels: List[Tuple[ttk.Label, ttk.Label]] = []
        self._stacked: Optional[bool] = None
        self._width: Optional[int] = None

    def fill(self, rows: Rows) -> None:
        for child in self._body.winfo_children():
            child.destroy()
        self._texts = list(rows)
        self._labels = [
            (ttk.Label(self._body, text=key, justify="left"),
             ttk.Label(self._body, text=value, style="Hint.TLabel",
                       justify="left"))
            for key, value in self._texts]
        self._stacked = None
        self._width = None

    def fits(self, font: tkfont.Font, width: int) -> bool:
        half = width // 2
        return all(font.measure(key) <= half - KEY_GAP
                   and all(font.measure(word) <= half
                           for word in value.split())
                   for key, value in self._texts)

    def arrange(self, width: int, stacked: bool) -> None:
        if (width, stacked) == (self._width, self._stacked):
            return
        self._width = width
        if stacked != self._stacked:
            self._stacked = stacked
            for r, (key, value) in enumerate(self._labels):
                if stacked:
                    key.grid(row=2 * r, column=0, columnspan=2, sticky="nw",
                             padx=0, pady=(STACK_GAP if r else 0, 0))
                    value.grid(row=2 * r + 1, column=0, columnspan=2,
                               sticky="nw", padx=0, pady=0)
                else:
                    key.grid(row=r, column=0, columnspan=1, sticky="nw",
                             padx=(0, KEY_GAP), pady=0)
                    value.grid(row=r, column=1, columnspan=1, sticky="nw",
                               padx=0, pady=0)
        key_wrap = width if stacked else width // 2 - KEY_GAP
        value_wrap = width if stacked else width // 2
        for key, value in self._labels:
            key.config(wraplength=max(1, key_wrap))
            value.config(wraplength=max(1, value_wrap))
