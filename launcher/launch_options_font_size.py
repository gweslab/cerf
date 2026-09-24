from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

from ui_dialogs import show_error
from launch_options_presets import (FONT_SIZE_SLIDER_MIN,
                                    FONT_SIZE_SLIDER_MAX)

DEFAULT_FONT_SIZE = 14


class FontSizeOptionBlock:
    @staticmethod
    def _is_optional_int(value: str) -> bool:
        if value in ("", "-"):
            return True
        body = value[1:] if value.startswith("-") else value
        return body.isdigit()

    def __init__(self, parent: tk.Misc, window: tk.Misc) -> None:
        self._window = window
        self._sync_guard = False
        self._enabled = True

        self.var_override = tk.BooleanVar(value=False)
        self.var_size = tk.StringVar(value=str(DEFAULT_FONT_SIZE))
        signed_vcmd = (window.register(self._is_optional_int), "%P")

        self.frame = ttk.Frame(parent)
        self.frame.columnconfigure(0, weight=1)
        self.check = ttk.Checkbutton(self.frame,
                                     text="Override system font size",
                                     variable=self.var_override,
                                     command=self._refresh_state)
        self.check.grid(row=0, column=0, columnspan=2, sticky="w")
        self.slider = ttk.Scale(self.frame, from_=FONT_SIZE_SLIDER_MIN,
                                to=FONT_SIZE_SLIDER_MAX, orient="horizontal",
                                style="Res.Horizontal.TScale",
                                command=self._on_slider)
        self.slider.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.entry = ttk.Entry(self.frame, textvariable=self.var_size,
                               width=5, validate="key",
                               validatecommand=signed_vcmd)
        self.entry.grid(row=1, column=1, sticky="e", padx=(8, 0), pady=(6, 0))
        self.var_size.trace_add("write", self._on_text_changed)
        self._sync_slider_to_text()

    def load(self, model: dict) -> None:
        if "font_size" in model:
            self.var_override.set(True)
            self.var_size.set(str(model["font_size"]))
        else:
            self.var_override.set(False)
            self.var_size.set(str(DEFAULT_FONT_SIZE))
        self._sync_slider_to_text()
        self._refresh_state()

    def store(self, model: dict) -> None:
        value = self._optional_value()
        if self.var_override.get() and value is not None:
            model["font_size"] = value
        else:
            model.pop("font_size", None)

    def validate(self) -> bool:
        if not self.var_override.get():
            return True
        if self._optional_value() is not None:
            return True
        show_error(self._window, "Invalid font size",
                   "Font size must be a whole number.")
        self.entry.focus_set()
        return False

    def apply_preset(self, value: int) -> None:
        self.var_override.set(True)
        self.var_size.set(str(value))
        self._sync_slider_to_text()
        self._refresh_state()

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self.check.config(state="normal" if enabled else "disabled")
        self._refresh_state()

    def _refresh_state(self) -> None:
        on = self._enabled and self.var_override.get()
        state = "normal" if on else "disabled"
        self.entry.config(state=state)
        self.slider.config(state=state)

    def _optional_value(self) -> Optional[int]:
        try:
            return int(self.var_size.get().strip(), 10)
        except ValueError:
            return None

    def _on_slider(self, value: str) -> None:
        if self._sync_guard:
            return
        self._sync_guard = True
        try:
            self.var_size.set(str(int(round(float(value)))))
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
            self.slider.set(max(FONT_SIZE_SLIDER_MIN,
                                min(FONT_SIZE_SLIDER_MAX, value)))
        finally:
            self._sync_guard = False
