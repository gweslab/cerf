from __future__ import annotations

import tkinter as tk
from typing import Callable, List, Optional

from choice_combo import ChoiceCombo
from rich_text import Segment, link, plain
from settings_card import SettingsRow
from ui_dialogs import show_bpp_help

BPP_CHOICES = (None, 8, 16, 24, 32)


def bpp_description(window: tk.Misc) -> List[Segment]:
    return [plain("A wrong value breaks the guest. "),
            link("Learn more", lambda: show_bpp_help(window))]


def bpp_label(value: Optional[int], auto_depth: Optional[int]) -> str:
    if value is None:
        return "Auto - {}bpp".format(auto_depth) if auto_depth else "Auto"
    return "{}bpp".format(value)


def model_bpp(model: dict) -> Optional[int]:
    value = model.get("bpp")
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


class BppOptionBlock:
    def __init__(self, row: SettingsRow,
                 on_change: Optional[Callable[[], None]] = None) -> None:
        self._auto_depth: Optional[int] = None
        self.combo = ChoiceCombo(row.frame, on_change=on_change)
        row.control(self.combo.widget)
        self._configure()

    def set_auto_depth(self, depth: Optional[int]) -> None:
        self._auto_depth = depth
        self._configure()

    def load(self, model: dict) -> None:
        self.combo.set(model_bpp(model))

    def store(self, model: dict) -> None:
        value = self.combo.get()
        if value is None:
            model.pop("bpp", None)
        else:
            model["bpp"] = value

    def set_enabled(self, enabled: bool) -> None:
        self.combo.set_enabled(enabled)

    def _configure(self) -> None:
        self.combo.configure(BPP_CHOICES,
                             lambda v: bpp_label(v, self._auto_depth))
