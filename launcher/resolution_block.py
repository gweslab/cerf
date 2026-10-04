from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional, Tuple

from choice_combo import ChoiceCombo
from launch_options_presets import RES_PRESETS
from number_dialog import ask_numbers
from settings_card import SettingsRow

Size = Tuple[int, int]

_NAMES = {(w, h): name for w, h, name in RES_PRESETS}
_SIZES = [(w, h) for w, h, _name in RES_PRESETS]


def resolution_label(size: Optional[Size], auto_size: Size) -> str:
    if size is None:
        return "Auto - {}x{}".format(*auto_size)
    return "{} - {}x{}".format(_NAMES.get(size, "Custom"), *size)


def model_size(model: dict) -> Optional[Size]:
    if "width" in model and "height" in model:
        return (model["width"], model["height"])
    return None


class ResolutionBlock:
    def __init__(self, row: SettingsRow, window: tk.Misc,
                 on_change: Optional[Callable[[], None]] = None) -> None:
        self._window = window
        self._auto_size: Size = (0, 0)
        self.combo = ChoiceCombo(row.frame, on_change=on_change,
                                 ask_custom=self._ask_custom)
        row.control(self.combo.widget)
        self._configure()

    def set_auto_size(self, size: Size) -> None:
        self._auto_size = size
        self._configure()

    def load(self, model: dict) -> None:
        self.combo.set(model_size(model))

    def store(self, model: dict) -> None:
        size = self.combo.get()
        if size is None:
            model.pop("width", None)
            model.pop("height", None)
        else:
            model["width"], model["height"] = size

    def set_enabled(self, enabled: bool) -> None:
        self.combo.set_enabled(enabled)

    def _configure(self) -> None:
        self.combo.configure(
            [None] + _SIZES,
            lambda size: resolution_label(size, self._auto_size))

    def _ask_custom(self, current: object) -> Optional[Size]:
        width, height = current if current is not None else self._auto_size
        values = ask_numbers(self._window, "Display resolution",
                             [("Width", width, "px"), ("Height", height, "px")])
        if values is None:
            return None
        return (values[0], values[1])
