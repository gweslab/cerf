"""The DPI-override sub-panel of the launch options: its widgets, the
entry/slider two-way sync, and its persisted field."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Optional

from ui_dialogs import show_error, show_dpi_help
from launch_options_presets import DPI_SLIDER_MIN, DPI_SLIDER_MAX


class DpiOptionBlock:
    def __init__(self, cfg: ttk.Frame, window: tk.Misc,
                 on_change: Callable[[], None], numeric_vcmd,
                 row_head: int, row_fields: int, row_sep: int):
        self._window = window
        self._on_change = on_change
        self._sync_guard = False
        self._locked = False

        self.var_override = tk.BooleanVar(value=False)
        self.var_dpi = tk.StringVar(value="96")

        self.head = ttk.Frame(cfg)
        self.head.grid(row=row_head, column=0, sticky="ew")
        self.head.columnconfigure(0, weight=1)
        self.check = ttk.Checkbutton(self.head, text="Override DPI",
                                     variable=self.var_override,
                                     command=self._on_override_changed)
        self.check.grid(row=0, column=0, sticky="w")
        self.help = ttk.Button(self.head, text="?", width=2, style="Help.TButton",
                               command=lambda: show_dpi_help(self._window))
        self.help.grid(row=0, column=1, sticky="e")

        self.fields = ttk.Frame(cfg)
        self.fields.grid(row=row_fields, column=0, sticky="ew", pady=(2, 0))
        self.fields.columnconfigure(3, weight=1)
        ttk.Label(self.fields, text="DPI").grid(row=0, column=0, sticky="w")
        self.entry = ttk.Entry(self.fields, textvariable=self.var_dpi, width=8,
                               validate="key", validatecommand=numeric_vcmd)
        self.entry.grid(row=0, column=1, sticky="w", padx=(4, 12))
        self.slider = ttk.Scale(self.fields, from_=DPI_SLIDER_MIN, to=DPI_SLIDER_MAX,
                                orient="horizontal", style="Res.Horizontal.TScale",
                                command=self._on_slider)
        self.slider.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        self.var_dpi.trace_add("write", self._on_text_changed)
        self.sync_slider_to_text()

        self.sep = ttk.Separator(cfg, orient="horizontal")
        self.sep.grid(row=row_sep, column=0, sticky="ew", pady=8)

    def lockables(self) -> List[tk.Widget]:
        return [self.check, self.help, self.entry, self.slider]

    def blocks(self) -> List[tk.Widget]:
        return [self.head, self.fields, self.sep]

    def restore(self, eff: dict) -> None:
        if "dpi" in eff:
            self.var_override.set(True)
            self.var_dpi.set(str(eff["dpi"]))
        else:
            self.var_override.set(False)
        self.sync_slider_to_text()

    def enabled(self) -> bool:
        return bool(self.var_override.get())

    def apply_preset(self, value: int) -> None:
        self.var_override.set(True)
        self.var_dpi.set(str(value))
        self.sync_slider_to_text()
        self.refresh_state(self._locked)

    def optional_value(self) -> Optional[int]:
        try:
            v = int(self.var_dpi.get().strip())
        except ValueError:
            return None
        return v if v > 0 else None

    def value_or_error(self) -> Optional[int]:
        raw = self.var_dpi.get().strip()
        try:
            value = int(raw, 10)
        except ValueError:
            value = 0
        if value < 1:
            show_error(self._window, "Invalid DPI",
                       "DPI must be a positive whole number.")
            self.entry.focus_set()
            return None
        return value

    def refresh_state(self, locked: bool) -> None:
        self._locked = locked
        if locked:
            self.entry.config(state="disabled")
            self.slider.config(state="disabled")
            return
        state = "normal" if self.var_override.get() else "disabled"
        self.entry.config(state=state)
        self.slider.config(state=state)

    def _on_override_changed(self) -> None:
        self.refresh_state(self._locked)
        self._on_change()

    def _on_slider(self, value: str) -> None:
        if self._sync_guard:
            return
        self._sync_guard = True
        try:
            self.var_dpi.set(str(int(round(float(value)))))
        finally:
            self._sync_guard = False
        self._on_change()

    def _on_text_changed(self, *_args: object) -> None:
        if self._sync_guard:
            return
        self.sync_slider_to_text()
        self._on_change()

    def sync_slider_to_text(self) -> None:
        try:
            dpi = int(self.var_dpi.get().strip())
        except ValueError:
            return
        self._sync_guard = True
        try:
            self.slider.set(max(DPI_SLIDER_MIN, min(DPI_SLIDER_MAX, dpi)))
        finally:
            self._sync_guard = False
