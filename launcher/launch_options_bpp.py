from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ui_dialogs import show_bpp_help

BPP_STOPS = (0, 8, 16, 24, 32)


def bpp_label(value: int) -> str:
    if value == 0:
        return "Auto"
    if value in BPP_STOPS:
        return "{} bpp".format(value)
    return "Custom - {} bpp".format(value)


def nearest_stop_index(value: int) -> int:
    if value in BPP_STOPS:
        return BPP_STOPS.index(value)
    return min(range(1, len(BPP_STOPS)),
               key=lambda i: abs(BPP_STOPS[i] - value))


class BppOptionBlock:
    def __init__(self, parent: tk.Misc, window: tk.Misc) -> None:
        self._window = window
        self._sync_guard = False
        self._value = 0

        self.frame = ttk.Frame(parent)
        self.frame.columnconfigure(0, weight=1)
        head = ttk.Frame(self.frame)
        head.grid(row=0, column=0, sticky="ew")
        head.columnconfigure(0, weight=1)
        ttk.Label(head, text="Color depth").grid(row=0, column=0, sticky="w")
        self.help = ttk.Button(head, text="?", width=2, style="Help.TButton",
                               command=lambda: show_bpp_help(self._window))
        self.help.grid(row=0, column=1, sticky="e")

        self.slider = ttk.Scale(self.frame, from_=0, to=len(BPP_STOPS) - 1,
                                orient="horizontal",
                                style="Res.Horizontal.TScale",
                                command=self._on_slider)
        self.slider.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.label = ttk.Label(self.frame, text=bpp_label(0),
                               style="Hint.TLabel")
        self.label.grid(row=2, column=0, sticky="w")

    def load(self, model: dict) -> None:
        value = model.get("bpp", 0)
        if not isinstance(value, int) or value < 0:
            value = 0
        self._set_value(value)

    def store(self, model: dict) -> None:
        if self._value:
            model["bpp"] = self._value
        else:
            model.pop("bpp", None)

    def value(self) -> int:
        return self._value

    def set_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.slider.config(state=state)
        self.help.config(state=state)

    def _set_value(self, value: int) -> None:
        self._value = value
        self._sync_guard = True
        try:
            self.slider.set(nearest_stop_index(value))
        finally:
            self._sync_guard = False
        self.label.config(text=bpp_label(value))

    def _on_slider(self, raw: str) -> None:
        if self._sync_guard:
            return
        index = max(0, min(len(BPP_STOPS) - 1, int(round(float(raw)))))
        if abs(float(raw) - index) > 1e-9:
            self.slider.set(index)
            return
        if BPP_STOPS[index] != self._value:
            self._set_value(BPP_STOPS[index])
