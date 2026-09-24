from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional, Tuple

from launch_options_presets import RES_PRESETS
from ui_dialogs import show_error

_AUTO = 0


class ResolutionBlock:
    def __init__(self, parent: tk.Misc, window: tk.Misc) -> None:
        self._window = window
        self._sync_guard = False
        self._enabled = True
        self._auto = True
        self._auto_size: Tuple[int, int] = (0, 0)

        numeric_vcmd = (window.register(self._is_optional_uint), "%P")
        self.var_width = tk.StringVar(value="")
        self.var_height = tk.StringVar(value="")

        self.frame = ttk.Frame(parent)
        self.frame.columnconfigure(0, weight=1)
        ttk.Label(self.frame, text="Display resolution").grid(
            row=0, column=0, sticky="w")
        self.slider = ttk.Scale(self.frame, from_=0, to=len(RES_PRESETS),
                                orient="horizontal",
                                style="Res.Horizontal.TScale",
                                command=self._on_slider)
        self.slider.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.preset_label = ttk.Label(self.frame, text="", style="Hint.TLabel")
        self.preset_label.grid(row=2, column=0, sticky="w")

        fields = ttk.Frame(self.frame)
        fields.grid(row=3, column=0, sticky="w", pady=(4, 0))
        ttk.Label(fields, text="Width").grid(row=0, column=0, sticky="w")
        self.width_entry = ttk.Entry(fields, textvariable=self.var_width,
                                     width=6, validate="key",
                                     validatecommand=numeric_vcmd)
        self.width_entry.grid(row=0, column=1, padx=(4, 2))
        ttk.Label(fields, text="px  ×  Height").grid(row=0, column=2)
        self.height_entry = ttk.Entry(fields, textvariable=self.var_height,
                                      width=6, validate="key",
                                      validatecommand=numeric_vcmd)
        self.height_entry.grid(row=0, column=3, padx=(4, 2))
        ttk.Label(fields, text="px").grid(row=0, column=4)
        self.var_width.trace_add("write", self._on_text_changed)
        self.var_height.trace_add("write", self._on_text_changed)

    def set_auto_size(self, size: Tuple[int, int]) -> None:
        self._auto_size = size
        if self._auto:
            self._show_auto()

    def load(self, model: dict) -> None:
        if "width" in model and "height" in model:
            self._auto = False
            self._set_text(model["width"], model["height"])
            self._sync_slider_to_text()
        else:
            self._auto = True
            self._show_auto()
        self._refresh_state()

    def store(self, model: dict) -> None:
        size = None if self._auto else self._size()
        if size is None:
            model.pop("width", None)
            model.pop("height", None)
        else:
            model["width"], model["height"] = size

    def validate(self) -> bool:
        if self._auto or self._size() is not None:
            return True
        show_error(self._window, "Invalid resolution",
                   "Width and height must be positive whole-pixel values.")
        self.width_entry.focus_set()
        return False

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self._refresh_state()

    def _refresh_state(self) -> None:
        self.slider.config(state="normal" if self._enabled else "disabled")
        fields = "normal" if self._enabled and not self._auto else "disabled"
        self.width_entry.config(state=fields)
        self.height_entry.config(state=fields)

    @staticmethod
    def _is_optional_uint(value: str) -> bool:
        return value == "" or value.isdigit()

    def _size(self) -> Optional[Tuple[int, int]]:
        try:
            w = int(self.var_width.get().strip(), 10)
            h = int(self.var_height.get().strip(), 10)
        except ValueError:
            return None
        if w < 1 or h < 1:
            return None
        return w, h

    def _set_text(self, w: int, h: int) -> None:
        self._sync_guard = True
        try:
            self.var_width.set(str(w))
            self.var_height.set(str(h))
        finally:
            self._sync_guard = False

    def _set_slider(self, index: int) -> None:
        self._sync_guard = True
        try:
            self.slider.set(index)
        finally:
            self._sync_guard = False

    def _show_auto(self) -> None:
        w, h = self._auto_size
        self._set_text(w, h)
        self._set_slider(_AUTO)
        self.preset_label.config(text="Auto")

    def _on_slider(self, value: str) -> None:
        if self._sync_guard:
            return
        index = max(0, min(len(RES_PRESETS), int(round(float(value)))))
        if abs(float(value) - index) > 1e-9:
            self.slider.set(index)
            return
        if index == _AUTO:
            self._auto = True
            self._show_auto()
        else:
            self._auto = False
            w, h = RES_PRESETS[index - 1]
            self._set_text(w, h)
            self.preset_label.config(text="{} × {}".format(w, h))
        self._refresh_state()

    def _on_text_changed(self, *_args: object) -> None:
        if not self._sync_guard:
            self._sync_slider_to_text()

    def _sync_slider_to_text(self) -> None:
        size = self._size()
        if size is None:
            self.preset_label.config(text="Custom")
            return
        if size in RES_PRESETS:
            self._set_slider(RES_PRESETS.index(size) + 1)
            self.preset_label.config(text="{} × {}".format(*size))
            return
        area = size[0] * size[1]
        nearest = min(range(len(RES_PRESETS)),
                      key=lambda i: abs(RES_PRESETS[i][0] * RES_PRESETS[i][1]
                                        - area))
        self._set_slider(nearest + 1)
        self.preset_label.config(text="Custom - {} × {}".format(*size))
