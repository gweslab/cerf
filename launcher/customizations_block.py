from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Optional, Tuple

from color_schemes import (COLOR_SCHEMES, CS_KEY_TO_LABEL, CS_LABEL_TO_KEY)
from launch_options_bpp import BppOptionBlock
from launch_options_dpi import DpiOptionBlock
from launch_options_font_size import FontSizeOptionBlock
from launch_options_presets import (RES_PRESETS, DEFAULT_SCREEN_WIDTH,
                                    DEFAULT_SCREEN_HEIGHT)
from ui_dialogs import show_color_scheme_help, show_error
import ui_theme as theme


CUSTOMIZATION_FIELDS = ("width", "height", "dpi", "font_size", "bpp",
                        "color_scheme")


class CustomizationsBlock:
    def __init__(self, parent: tk.Misc, window: tk.Misc,
                 on_change: Callable[[], None], row: int = 0):
        self._window = window
        self._on_change = on_change
        self._sync_guard = False
        self._locked = False
        self._guest_additions = True

        frame = ttk.Frame(parent)
        frame.grid(row=row, column=0, sticky="ew")
        frame.columnconfigure(0, weight=1)
        self.frame = frame

        numeric_vcmd = (window.register(self._is_optional_uint), "%P")
        signed_vcmd = (window.register(FontSizeOptionBlock.is_optional_int),
                       "%P")

        self.var_width = tk.StringVar(value=str(DEFAULT_SCREEN_WIDTH))
        self.var_height = tk.StringVar(value=str(DEFAULT_SCREEN_HEIGHT))
        self.var_color_scheme = tk.StringVar(value=COLOR_SCHEMES[0][1])

        self.res_note = ttk.Label(frame, text="Resolution override:")
        self.res_note.grid(row=0, column=0, sticky="w")

        res_fields = self.res_fields = ttk.Frame(frame)
        res_fields.grid(row=1, column=0, sticky="ew", pady=(2, 0))
        res_fields.columnconfigure(5, weight=1)
        self.width_entry = ttk.Entry(res_fields, textvariable=self.var_width,
                                     width=8, validate="key",
                                     validatecommand=numeric_vcmd)
        self.height_entry = ttk.Entry(res_fields, textvariable=self.var_height,
                                      width=8, validate="key",
                                      validatecommand=numeric_vcmd)
        ttk.Label(res_fields, text="Width").grid(row=0, column=0, sticky="w")
        self.width_entry.grid(row=0, column=1, sticky="w", padx=(4, 4))
        ttk.Label(res_fields, text="px").grid(row=0, column=2, sticky="w",
                                              padx=(0, 12))
        ttk.Label(res_fields, text="Height").grid(row=0, column=3, sticky="w")
        self.height_entry.grid(row=0, column=4, sticky="w", padx=(4, 4))
        ttk.Label(res_fields, text="px").grid(row=0, column=5, sticky="w")

        self.res_slider = ttk.Scale(res_fields, from_=0, to=len(RES_PRESETS) - 1,
                                    orient="horizontal",
                                    style="Res.Horizontal.TScale",
                                    command=self._on_res_slider)
        self.res_slider.grid(row=1, column=0, columnspan=6, sticky="ew",
                             pady=(8, 0))
        self.res_preset_label = ttk.Label(res_fields, text="",
                                          style="Hint.TLabel")
        self.res_preset_label.grid(row=2, column=0, columnspan=6, sticky="w")
        self.var_width.trace_add("write", self._on_res_text_changed)
        self.var_height.trace_add("write", self._on_res_text_changed)
        self._sync_slider_to_text()

        self.res_sep = ttk.Separator(frame, orient="horizontal")
        self.res_sep.grid(row=2, column=0, sticky="ew", pady=8)

        self.bpp = BppOptionBlock(frame, window, self._on_change,
                                  row_head=3, row_fields=4, row_sep=5)
        self.dpi = DpiOptionBlock(frame, window, self._on_change, numeric_vcmd,
                                  row_head=6, row_fields=7, row_sep=8)
        self.font_size = FontSizeOptionBlock(frame, window, self._on_change,
                                             signed_vcmd, row_head=9,
                                             row_fields=10, row_sep=11)

        cs_row = self.cs_row = ttk.Frame(frame)
        cs_row.grid(row=12, column=0, sticky="ew")
        cs_row.columnconfigure(1, weight=1)
        ttk.Label(cs_row, text="Color scheme:").grid(row=0, column=0,
                                                     sticky="w", padx=(0, 6))
        self.color_scheme_combo = ttk.Combobox(
            cs_row, state="readonly", textvariable=self.var_color_scheme,
            values=[label for (_key, label) in COLOR_SCHEMES])
        self.color_scheme_combo.grid(row=0, column=1, sticky="ew")
        self.cs_help = ttk.Button(
            cs_row, text="?", width=2, style="Help.TButton",
            command=lambda: show_color_scheme_help(self._window))
        self.cs_help.grid(row=0, column=2, sticky="e", padx=(4, 0))
        self.color_scheme_combo.bind("<<ComboboxSelected>>",
                                     lambda _e: self._on_change())

    def lockables(self) -> List[tk.Widget]:
        return ([self.width_entry, self.height_entry, self.res_slider]
                + self.bpp.lockables() + self.dpi.lockables()
                + self.font_size.lockables()
                + [self.color_scheme_combo, self.cs_help])

    def restore(self, eff: dict) -> None:
        self.var_width.set(str(eff["width"]))
        self.var_height.set(str(eff["height"]))
        self.var_color_scheme.set(
            CS_KEY_TO_LABEL.get(eff.get("color_scheme", ""),
                                COLOR_SCHEMES[0][1]))
        self.dpi.restore(eff)
        self.font_size.restore(eff)
        self.bpp.restore(eff)
        self._sync_slider_to_text()

    def collect(self, out: dict) -> None:
        out["color_scheme"] = CS_LABEL_TO_KEY.get(self.var_color_scheme.get(), "")
        w = self._optional_uint(self.var_width)
        if w is not None:
            out["width"] = w
        h = self._optional_uint(self.var_height)
        if h is not None:
            out["height"] = h
        if self._guest_additions and self.dpi.enabled():
            d = self.dpi.optional_value()
            if d is not None:
                out["dpi"] = d
        if self._guest_additions and self.font_size.enabled():
            f = self.font_size.optional_value()
            if f is not None:
                out["font_size"] = f
        b = self.bpp.optional_value()
        if b is not None:
            out["bpp"] = b

    def refresh_state(self, guest_additions: bool, resolution_available: bool,
                      color_scheme_available: bool, locked: bool) -> None:
        self._guest_additions = guest_additions
        self._locked = locked

        res_visible = resolution_available or guest_additions
        self._set_visible(res_visible, self.res_note, self.res_fields,
                          self.res_sep)
        self.res_note.config(text="CERF display driver resolution:"
                             if guest_additions else "Resolution override:")
        self.res_preset_label.config(foreground=theme.FG_DIM)

        self._set_visible(res_visible, *self.bpp.blocks())
        self.bpp.refresh_state(locked)

        self._set_visible(guest_additions, *self.dpi.blocks())
        self.dpi.refresh_state(locked)

        self._set_visible(guest_additions, *self.font_size.blocks())
        self.font_size.refresh_state(locked)

        self._set_visible(guest_additions and color_scheme_available,
                          self.cs_row)
        self.color_scheme_combo.config(
            state="disabled" if locked else "readonly")

        for entry in (self.width_entry, self.height_entry, self.res_slider):
            entry.config(state="disabled" if locked else "normal")

    def validate(self) -> bool:
        if self._resolution_value(self.var_width, self.width_entry,
                                  "Width") is None:
            return False
        if self._resolution_value(self.var_height, self.height_entry,
                                  "Height") is None:
            return False
        if self._guest_additions and self.dpi.enabled():
            if self.dpi.value_or_error() is None:
                return False
        if self._guest_additions and self.font_size.enabled():
            if self.font_size.value_or_error() is None:
                return False
        return True

    def resolution(self) -> Optional[Tuple[int, int]]:
        w = self._resolution_value(self.var_width, self.width_entry, "Width")
        if w is None:
            return None
        h = self._resolution_value(self.var_height, self.height_entry, "Height")
        if h is None:
            return None
        return (w, h)

    def dpi_value_or_error(self) -> Optional[int]:
        return self.dpi.value_or_error()

    def dpi_enabled(self) -> bool:
        return self.dpi.enabled()

    def font_size_value_or_error(self) -> Optional[int]:
        return self.font_size.value_or_error()

    def font_size_enabled(self) -> bool:
        return self.font_size.enabled()

    def bpp_value(self) -> Optional[int]:
        return self.bpp.optional_value()

    def color_scheme_key(self) -> str:
        return CS_LABEL_TO_KEY.get(self.var_color_scheme.get(), "")

    def _set_visible(self, visible: bool, *widgets: tk.Widget) -> None:
        for w in widgets:
            if visible:
                w.grid()
            else:
                w.grid_remove()

    def _is_optional_uint(self, value: str) -> bool:
        return value == "" or value.isdigit()

    def _optional_uint(self, var: tk.StringVar) -> Optional[int]:
        try:
            v = int(var.get().strip())
        except ValueError:
            return None
        return v if v > 0 else None

    def _resolution_value(self, var: tk.StringVar, entry: ttk.Entry,
                          label: str) -> Optional[int]:
        raw = var.get().strip()
        value = 0
        try:
            value = int(raw, 10)
        except ValueError:
            value = 0
        if value < 1:
            show_error(self._window, "Invalid resolution",
                       "{} must be a positive whole-pixel value.".format(label))
            entry.focus_set()
            return None
        self._sync_guard = True
        try:
            var.set(str(value))
        finally:
            self._sync_guard = False
        return value

    def _on_res_slider(self, value: str) -> None:
        if self._sync_guard:
            return
        index = max(0, min(len(RES_PRESETS) - 1, int(round(float(value)))))
        if abs(float(value) - index) > 1e-9:
            self.res_slider.set(index)
            return
        w, h = RES_PRESETS[index]
        self._sync_guard = True
        try:
            self.var_width.set(str(w))
            self.var_height.set(str(h))
        finally:
            self._sync_guard = False
        self.res_preset_label.config(text="{} × {}".format(w, h))
        self._on_change()

    def _on_res_text_changed(self, *_args: object) -> None:
        if self._sync_guard:
            return
        self._sync_slider_to_text()
        self._on_change()

    def _sync_slider_to_text(self) -> None:
        try:
            w = int(self.var_width.get().strip())
            h = int(self.var_height.get().strip())
        except ValueError:
            self.res_preset_label.config(text="Custom")
            return
        self._sync_guard = True
        try:
            if (w, h) in RES_PRESETS:
                self.res_slider.set(RES_PRESETS.index((w, h)))
                self.res_preset_label.config(text="{} × {}".format(w, h))
            else:
                area = w * h
                nearest = min(range(len(RES_PRESETS)),
                              key=lambda i: abs(RES_PRESETS[i][0]
                                                * RES_PRESETS[i][1] - area))
                self.res_slider.set(nearest)
                self.res_preset_label.config(
                    text="Custom - {} × {}".format(w, h))
        finally:
            self._sync_guard = False
