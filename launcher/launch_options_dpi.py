from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional

from choice_combo import ChoiceCombo
from launch_options_presets import DPI_BASE, DPI_SCALE_PERCENTS
from number_dialog import ask_numbers
from settings_card import SettingsRow

_PRESETS = [DPI_BASE * percent // 100 for percent in DPI_SCALE_PERCENTS]


def dpi_label(dpi: Optional[int]) -> str:
    if dpi is None:
        return "Default"
    return "{}% - {} DPI".format(int(round(dpi * 100.0 / DPI_BASE)), dpi)


def model_dpi(model: dict) -> Optional[int]:
    value = model.get("dpi")
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


class DpiOptionBlock:
    def __init__(self, row: SettingsRow, window: tk.Misc,
                 on_change: Optional[Callable[[], None]] = None) -> None:
        self._window = window
        self.combo = ChoiceCombo(row.frame, on_change=on_change,
                                 ask_custom=self._ask_custom)
        row.control(self.combo.widget)
        self.combo.configure([None] + _PRESETS, dpi_label)

    def get(self) -> Optional[int]:
        return self.combo.get()

    def set(self, dpi: Optional[int]) -> None:
        self.combo.set(dpi)

    def load(self, model: dict) -> None:
        self.combo.set(model_dpi(model))

    def store(self, model: dict) -> None:
        value = self.combo.get()
        if value is None:
            model.pop("dpi", None)
        else:
            model["dpi"] = value

    def set_enabled(self, enabled: bool) -> None:
        self.combo.set_enabled(enabled)

    def _ask_custom(self, current: object) -> Optional[int]:
        initial = current if current is not None else DPI_BASE
        values = ask_numbers(self._window, "DPI", [("DPI", initial, "")])
        return None if values is None else values[0]
