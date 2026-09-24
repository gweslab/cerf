from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

from ui_dialogs import show_error, show_dpi_help
from launch_options_presets import DPI_SLIDER_MIN, DPI_SLIDER_MAX

DEFAULT_DPI = 96


class DpiOptionBlock:
    def __init__(self, parent: tk.Misc, window: tk.Misc) -> None:
        self._window = window
        self._sync_guard = False
        self._enabled = True

        self.var_override = tk.BooleanVar(value=False)
        self.var_dpi = tk.StringVar(value=str(DEFAULT_DPI))
        numeric_vcmd = (window.register(self._is_optional_uint), "%P")

        self.frame = ttk.Frame(parent)
        self.frame.columnconfigure(0, weight=1)
        head = ttk.Frame(self.frame)
        head.grid(row=0, column=0, sticky="ew")
        head.columnconfigure(0, weight=1)
        self.check = ttk.Checkbutton(head, text="Override DPI",
                                     variable=self.var_override,
                                     command=self._refresh_state)
        self.check.grid(row=0, column=0, sticky="w")
        self.help = ttk.Button(head, text="?", width=2, style="Help.TButton",
                               command=lambda: show_dpi_help(self._window))
        self.help.grid(row=0, column=1, sticky="e")

        self.slider = ttk.Scale(self.frame, from_=DPI_SLIDER_MIN,
                                to=DPI_SLIDER_MAX, orient="horizontal",
                                style="Res.Horizontal.TScale",
                                command=self._on_slider)
        self.slider.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.entry = ttk.Entry(self.frame, textvariable=self.var_dpi, width=6,
                               validate="key", validatecommand=numeric_vcmd)
        self.entry.grid(row=2, column=0, sticky="w", pady=(4, 0))
        self.var_dpi.trace_add("write", self._on_text_changed)
        self._sync_slider_to_text()

    def load(self, model: dict) -> None:
        if "dpi" in model:
            self.var_override.set(True)
            self.var_dpi.set(str(model["dpi"]))
        else:
            self.var_override.set(False)
            self.var_dpi.set(str(DEFAULT_DPI))
        self._sync_slider_to_text()
        self._refresh_state()

    def store(self, model: dict) -> None:
        value = self._optional_value()
        if self.var_override.get() and value is not None:
            model["dpi"] = value
        else:
            model.pop("dpi", None)

    def validate(self) -> bool:
        if not self.var_override.get():
            return True
        if self._optional_value() is not None:
            return True
        show_error(self._window, "Invalid DPI",
                   "DPI must be a positive whole number.")
        self.entry.focus_set()
        return False

    def apply_preset(self, value: int) -> None:
        self.var_override.set(True)
        self.var_dpi.set(str(value))
        self._sync_slider_to_text()
        self._refresh_state()

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        state = "normal" if enabled else "disabled"
        self.check.config(state=state)
        self.help.config(state=state)
        self._refresh_state()

    def _refresh_state(self) -> None:
        on = self._enabled and self.var_override.get()
        state = "normal" if on else "disabled"
        self.entry.config(state=state)
        self.slider.config(state=state)

    @staticmethod
    def _is_optional_uint(value: str) -> bool:
        return value == "" or value.isdigit()

    def _optional_value(self) -> Optional[int]:
        try:
            v = int(self.var_dpi.get().strip(), 10)
        except ValueError:
            return None
        return v if v > 0 else None

    def _on_slider(self, value: str) -> None:
        if self._sync_guard:
            return
        self._sync_guard = True
        try:
            self.var_dpi.set(str(int(round(float(value)))))
        finally:
            self._sync_guard = False

    def _on_text_changed(self, *_args: object) -> None:
        if not self._sync_guard:
            self._sync_slider_to_text()

    def _sync_slider_to_text(self) -> None:
        value = self._optional_value()
        if value is None:
            return
        self._sync_guard = True
        try:
            self.slider.set(max(DPI_SLIDER_MIN, min(DPI_SLIDER_MAX, value)))
        finally:
            self._sync_guard = False
