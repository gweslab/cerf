from __future__ import annotations

import tkinter as tk
import webbrowser
from tkinter import ttk
from typing import Callable, Tuple

from color_schemes import COLOR_SCHEMES, CS_KEY_TO_LABEL, CS_LABEL_TO_KEY
from launch_options_bpp import BppOptionBlock
from launch_options_dpi import DpiOptionBlock
from launch_options_font_size import FontSizeOptionBlock
from launch_options_presets import SCALE_PRESETS
from resolution_block import ResolutionBlock
from share_folder_block import ShareFolderBlock
from rich_text import RichText, link, plain
from ui_dialogs import GUEST_ADDITIONS_URL, show_color_scheme_help

PAGE_GUEST_ADDITIONS = "guest_additions"

_SCHEMES = COLOR_SCHEMES[1:]


class GuestAdditionsPage:
    key = PAGE_GUEST_ADDITIONS
    title = "Guest Additions"

    def __init__(self, parent: tk.Misc, window: tk.Misc,
                 color_scheme_available: bool,
                 on_toggled: Callable[[], None]) -> None:
        self._on_toggled = on_toggled
        self._color_scheme_available = color_scheme_available
        self._enabled = True
        self._toggle_locked = False

        self.var_enabled = tk.BooleanVar(value=False)
        self.var_cs_override = tk.BooleanVar(value=False)
        self.var_cs = tk.StringVar(value=_SCHEMES[0][1])

        self.frame = ttk.Frame(parent)
        self.frame.columnconfigure(0, weight=1)

        head = ttk.Frame(self.frame)
        head.grid(row=0, column=0, sticky="ew")
        self.check = ttk.Checkbutton(head, text="Enable Guest Additions",
                                     variable=self.var_enabled,
                                     command=self._on_check,
                                     style="Guest.TCheckbutton")
        self.check.grid(row=0, column=0, sticky="w")
        head.columnconfigure(0, weight=1)
        RichText(head, [
            plain("The Guest Additions feature modifies the ROM with the "
                  "emulator's own video driver and a big set of features. "),
            link("Learn more", lambda: webbrowser.open(GUEST_ADDITIONS_URL)),
        ]).grid(row=1, column=0, sticky="ew", pady=(4, 0))

        body = self.body = ttk.Frame(self.frame)
        body.grid(row=1, column=0, sticky="ew")
        body.columnconfigure(0, weight=1)

        self._rule(body, 0)
        self.share = ShareFolderBlock(body, window)
        self.share.frame.grid(row=1, column=0, sticky="ew")

        self._rule(body, 2)
        self.resolution = ResolutionBlock(body, window)
        self.resolution.frame.grid(row=3, column=0, sticky="ew")

        self._rule(body, 4)
        depth = ttk.Frame(body)
        depth.grid(row=5, column=0, sticky="ew")
        depth.columnconfigure(0, weight=1, uniform="half")
        depth.columnconfigure(2, weight=1, uniform="half")
        self.bpp = BppOptionBlock(depth, window)
        self.bpp.frame.grid(row=0, column=0, sticky="new", padx=(0, 8))
        self._vrule(depth, 1)
        self.dpi = DpiOptionBlock(depth, window)
        self.dpi.frame.grid(row=0, column=2, sticky="new", padx=(8, 0))

        self._rule(body, 6)
        look = ttk.Frame(body)
        look.grid(row=7, column=0, sticky="ew")
        look.columnconfigure(0, weight=1, uniform="half")
        look.columnconfigure(2, weight=1, uniform="half")
        self.font_size = FontSizeOptionBlock(look, window)
        self.font_size.frame.grid(row=0, column=0, sticky="new", padx=(0, 8))
        self.cs_sep = self._vrule(look, 1)
        cs = self.cs_frame = ttk.Frame(look)
        cs.grid(row=0, column=2, sticky="new", padx=(8, 0))
        cs.columnconfigure(0, weight=1)
        self.cs_check = ttk.Checkbutton(cs, text="Override color scheme",
                                        variable=self.var_cs_override,
                                        command=self._refresh_cs)
        self.cs_check.grid(row=0, column=0, sticky="w")
        self.cs_help = ttk.Button(
            cs, text="?", width=2, style="Help.TButton",
            command=lambda: show_color_scheme_help(window))
        self.cs_help.grid(row=0, column=1, sticky="e")
        self.cs_combo = ttk.Combobox(cs, state="readonly",
                                     textvariable=self.var_cs,
                                     values=[label for _k, label in _SCHEMES])
        self.cs_combo.grid(row=1, column=0, columnspan=2, sticky="ew",
                           pady=(6, 0))

        self._rule(body, 8)
        presets = ttk.Frame(body)
        presets.grid(row=9, column=0, sticky="ew")
        ttk.Label(presets, text="Set a preset",
                  font=("Segoe UI", 9, "bold")).grid(row=0, column=0,
                                                     columnspan=4, sticky="w")
        ttk.Label(presets,
                  text="Adopt settings above for a high DPI experience",
                  style="Hint.TLabel").grid(row=1, column=0, columnspan=4,
                                            sticky="w")
        self.preset_buttons = []
        for i, (label, dpi, font) in enumerate(SCALE_PRESETS):
            b = ttk.Button(presets, text="Adapt for {}".format(label),
                           command=lambda d=dpi, f=font: self._preset(d, f))
            b.grid(row=2, column=i, sticky="w", padx=(0, 6), pady=(6, 0))
            self.preset_buttons.append(b)

        if not color_scheme_available:
            self.cs_sep.grid_remove()
            cs.grid_remove()

    @staticmethod
    def _rule(parent: tk.Misc, row: int) -> ttk.Separator:
        sep = ttk.Separator(parent, orient="horizontal")
        sep.grid(row=row, column=0, sticky="ew", pady=10)
        return sep

    @staticmethod
    def _vrule(parent: tk.Misc, column: int) -> ttk.Separator:
        sep = ttk.Separator(parent, orient="vertical")
        sep.grid(row=0, column=column, sticky="ns")
        return sep

    def lock_toggle(self) -> None:
        self._toggle_locked = True
        self.check.config(state="disabled")

    def set_auto_size(self, size: Tuple[int, int]) -> None:
        self.resolution.set_auto_size(size)

    def load(self, model: dict) -> None:
        self.var_enabled.set(bool(model.get("guest_additions", False)))
        self.share.load(model)
        self.resolution.load(model)
        self.bpp.load(model)
        self.dpi.load(model)
        self.font_size.load(model)
        key = model.get("color_scheme", "")
        self.var_cs_override.set(bool(key) and key in CS_KEY_TO_LABEL)
        if self.var_cs_override.get():
            self.var_cs.set(CS_KEY_TO_LABEL[key])
        self._refresh_body()

    def store(self, model: dict) -> None:
        model["guest_additions"] = self.var_enabled.get()
        self.share.store(model)
        self.resolution.store(model)
        self.bpp.store(model)
        self.dpi.store(model)
        self.font_size.store(model)
        if self._color_scheme_available and self.var_cs_override.get():
            model["color_scheme"] = CS_LABEL_TO_KEY.get(self.var_cs.get(), "")
        elif self._color_scheme_available:
            model["color_scheme"] = ""

    def validate(self) -> bool:
        if not self.var_enabled.get():
            return True
        return (self.resolution.validate() and self.dpi.validate()
                and self.font_size.validate())

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self.check.config(state="normal" if enabled and not self._toggle_locked
                          else "disabled")
        for block in (self.share, self.resolution, self.bpp, self.dpi,
                      self.font_size):
            block.set_enabled(enabled)
        for b in self.preset_buttons:
            b.config(state="normal" if enabled else "disabled")
        self.cs_check.config(state="normal" if enabled else "disabled")
        self.cs_help.config(state="normal" if enabled else "disabled")
        self._refresh_cs()

    def _refresh_cs(self) -> None:
        on = self._enabled and self.var_cs_override.get()
        self.cs_combo.config(state="readonly" if on else "disabled")

    def _refresh_body(self) -> None:
        if self.var_enabled.get():
            self.body.grid()
        else:
            self.body.grid_remove()
        self._refresh_cs()

    def _on_check(self) -> None:
        self._refresh_body()
        self._on_toggled()

    def _preset(self, dpi: int, font: int) -> None:
        self.dpi.apply_preset(dpi)
        self.font_size.apply_preset(font)
