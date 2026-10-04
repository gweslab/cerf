from __future__ import annotations

import tkinter as tk
import webbrowser
from typing import Callable, Optional, Tuple

from choice_combo import ChoiceCombo
from color_schemes import COLOR_SCHEME_KEYS, color_scheme_label
from launch_options_bpp import BppOptionBlock, bpp_description
from launch_options_dpi import DpiOptionBlock
from launch_options_font_size import FontSizeOptionBlock
from launch_options_presets import SCALE_PRESETS
from resolution_block import ResolutionBlock
from rich_text import link, plain
from settings_card import SettingsColumn, switch
from share_folder_block import ShareFolderBlock
from ui_dialogs import GUEST_ADDITIONS_URL

PAGE_GUEST_ADDITIONS = "guest_additions"

_CLEARTYPE_LABELS = {None: "Default", True: "Enabled", False: "Disabled"}


def cleartype_label(value: Optional[bool]) -> str:
    return _CLEARTYPE_LABELS[value]


def model_cleartype(model: dict) -> Optional[bool]:
    value = model.get("cleartype")
    return value if isinstance(value, bool) else None


def _preset_label(index: Optional[int]) -> str:
    if index is None:
        return "Custom"
    name, dpi, _font = SCALE_PRESETS[index]
    return "{} / {} DPI".format(name, dpi)


class GuestAdditionsPage:
    key = PAGE_GUEST_ADDITIONS
    title = "Guest Additions"

    def __init__(self, parent: tk.Misc, window: tk.Misc,
                 on_toggled: Callable[[], None]) -> None:
        self._on_toggled = on_toggled
        self._enabled = True
        self._toggle_locked = False
        self.var_enabled = tk.BooleanVar(value=False)

        page = SettingsColumn(parent)
        self.frame = page.frame
        row = page.group().row("Enable Guest Additions", [
            plain("Replace the ROM's video driver with the CERF driver for a "
                  "better experience. "),
            link("Learn more", lambda: webbrowser.open(GUEST_ADDITIONS_URL))])
        self.check = switch(row.frame, self.var_enabled, self._on_check)
        row.control(self.check, wide=False)

        body = self.body = page.column()
        body.section("Storage")
        self.share = ShareFolderBlock(body.group(), window)

        body.section("Screen")
        screen = body.group()
        self.resolution = ResolutionBlock(screen.row("Display resolution"),
                                          window)
        self.bpp = BppOptionBlock(screen.row("Color depth",
                                             bpp_description(window)))

        body.section("UI customizations")
        ui = body.group()
        ui.note("Most of these properties are hacks. They work only on some "
                "Windows CE versions or ROMs. Change them at your own risk.")
        row = ui.row("Preset", [
            plain("Optimize the settings below for a high DPI screen.")])
        self.preset = ChoiceCombo(row.frame, on_change=self._on_preset)
        row.control(self.preset.widget)
        self.preset.configure(list(range(len(SCALE_PRESETS))), _preset_label)
        self.dpi = DpiOptionBlock(
            ui.row("DPI", [plain("Override the screen density.")]), window,
            on_change=self._sync_preset)
        self.font_size = FontSizeOptionBlock(
            ui.row("Font size", [plain("Override the system font size.")]),
            on_change=self._sync_preset)
        row = ui.row("ClearType", [
            plain("Force font antialiasing on or off.")])
        self.cleartype = ChoiceCombo(row.frame, on_change=self._sync_preset)
        row.control(self.cleartype.widget)
        self.cleartype.configure([None, True, False], cleartype_label)
        row = ui.row("Color scheme", [
            plain("Colorize a grayscale device with a Windows color "
                  "scheme.")])
        self.color_scheme = ChoiceCombo(row.frame)
        row.control(self.color_scheme.widget)
        self.color_scheme.configure(COLOR_SCHEME_KEYS, color_scheme_label)

    def lock_toggle(self) -> None:
        self._toggle_locked = True
        self.check.config(state="disabled")

    def set_auto_size(self, size: Tuple[int, int]) -> None:
        self.resolution.set_auto_size(size)

    def set_auto_depth(self, depth: int) -> None:
        self.bpp.set_auto_depth(depth)

    def load(self, model: dict) -> None:
        self.var_enabled.set(bool(model.get("guest_additions", False)))
        self.share.load(model)
        self.resolution.load(model)
        self.bpp.load(model)
        self.dpi.load(model)
        self.font_size.load(model)
        self.cleartype.set(model_cleartype(model))
        self.color_scheme.set(model.get("color_scheme", ""))
        self._sync_preset()
        self._refresh_body()

    def store(self, model: dict) -> None:
        model["guest_additions"] = self.var_enabled.get()
        self.share.store(model)
        self.resolution.store(model)
        self.bpp.store(model)
        self.dpi.store(model)
        self.font_size.store(model)
        cleartype = self.cleartype.get()
        if cleartype is None:
            model.pop("cleartype", None)
        else:
            model["cleartype"] = cleartype
        model["color_scheme"] = self.color_scheme.get()

    def validate(self) -> bool:
        if not self.var_enabled.get():
            return True
        return self.share.validate()

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self.check.config(state="normal" if enabled and not self._toggle_locked
                          else "disabled")
        for block in (self.share, self.resolution, self.bpp, self.dpi,
                      self.font_size):
            block.set_enabled(enabled)
        for combo in (self.preset, self.cleartype, self.color_scheme):
            combo.set_enabled(enabled)

    def _refresh_body(self) -> None:
        if self.var_enabled.get():
            self.body.frame.grid()
        else:
            self.body.frame.grid_remove()

    def _on_check(self) -> None:
        self._refresh_body()
        self._on_toggled()

    def _on_preset(self) -> None:
        index = self.preset.get()
        if index is None:
            return
        _name, dpi, font = SCALE_PRESETS[index]
        self.dpi.set(dpi)
        self.font_size.set(font)
        self.cleartype.set(True)

    def _sync_preset(self) -> None:
        current = (self.dpi.get(), self.font_size.get(), self.cleartype.get())
        match = None
        for index, (_name, dpi, font) in enumerate(SCALE_PRESETS):
            if current == (dpi, font, True):
                match = index
        self.preset.set(match)
