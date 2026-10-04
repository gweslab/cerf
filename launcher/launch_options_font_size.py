from __future__ import annotations

from typing import Callable, Optional

from choice_combo import ChoiceCombo
from launch_options_presets import FONT_SIZE_MAX, FONT_SIZE_MIN
from settings_card import SettingsRow


def font_size_label(size: Optional[int]) -> str:
    return "Default" if size is None else str(size)


def model_font_size(model: dict) -> Optional[int]:
    value = model.get("font_size")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


class FontSizeOptionBlock:
    def __init__(self, row: SettingsRow,
                 on_change: Optional[Callable[[], None]] = None) -> None:
        self.combo = ChoiceCombo(row.frame, on_change=on_change)
        row.control(self.combo.widget)
        self.combo.configure(
            [None] + list(range(FONT_SIZE_MIN, FONT_SIZE_MAX + 1)),
            font_size_label)

    def get(self) -> Optional[int]:
        return self.combo.get()

    def set(self, size: Optional[int]) -> None:
        self.combo.set(size)

    def load(self, model: dict) -> None:
        self.combo.set(model_font_size(model))

    def store(self, model: dict) -> None:
        value = self.combo.get()
        if value is None:
            model.pop("font_size", None)
        else:
            model["font_size"] = value

    def set_enabled(self, enabled: bool) -> None:
        self.combo.set_enabled(enabled)
