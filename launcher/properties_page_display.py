from __future__ import annotations

import tkinter as tk
from typing import Tuple

from launch_options_bpp import BppOptionBlock, bpp_description
from resolution_block import ResolutionBlock
from settings_card import SettingsColumn

PAGE_DISPLAY = "display"


class DisplayPage:
    key = PAGE_DISPLAY
    title = "Display"

    def __init__(self, parent: tk.Misc, window: tk.Misc) -> None:
        page = SettingsColumn(parent)
        self.frame = page.frame
        group = page.group()
        self.resolution = ResolutionBlock(group.row("Display resolution"),
                                          window)
        self.bpp = BppOptionBlock(group.row("Color depth",
                                            bpp_description(window)))

    def set_auto_size(self, size: Tuple[int, int]) -> None:
        self.resolution.set_auto_size(size)

    def load(self, model: dict) -> None:
        self.resolution.load(model)
        self.bpp.load(model)

    def store(self, model: dict) -> None:
        self.resolution.store(model)
        self.bpp.store(model)

    def validate(self) -> bool:
        return True

    def set_enabled(self, enabled: bool) -> None:
        self.resolution.set_enabled(enabled)
        self.bpp.set_enabled(enabled)
