from __future__ import annotations
from i18n import t

import tkinter as tk
from typing import Callable, List, Optional

from choice_combo import ChoiceCombo
from rich_text import Segment, link, plain
from settings_card import SettingsRow
from ui_dialogs import show_bpp_help

BPP_CHOICES = (None, 8, 16, 24, 32)


def bpp_description(window: tk.Misc) -> List[Segment]:
    return [plain(t("launcher.launch_options_bpp.a_wrong_value_breaks_the_guest")),
            link(t("launcher.launch_options_bpp.learn_more"), lambda: show_bpp_help(window))]


def bpp_label(value: Optional[int], auto_depth: Optional[int]) -> str:
    if value is None:
        return t('launcher.launch_options_bpp.auto_auto_depth_bpp', auto_depth=auto_depth) if auto_depth else t("common.auto")
    return t('launcher.launch_options_bpp.value_bpp', value=value)


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
