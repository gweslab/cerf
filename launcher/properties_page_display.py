from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Tuple

from launch_options_bpp import BppOptionBlock
from resolution_block import ResolutionBlock

PAGE_DISPLAY = "display"


class DisplayPage:
    key = PAGE_DISPLAY
    title = "Display"

    def __init__(self, parent: tk.Misc, window: tk.Misc) -> None:
        self.frame = ttk.Frame(parent)
        self.frame.columnconfigure(0, weight=1)
        self.resolution = ResolutionBlock(self.frame, window)
        self.resolution.frame.grid(row=0, column=0, sticky="new")
        ttk.Separator(self.frame, orient="horizontal").grid(
            row=1, column=0, sticky="ew", pady=10)
        self.bpp = BppOptionBlock(self.frame, window)
        self.bpp.frame.grid(row=2, column=0, sticky="new")

    def set_auto_size(self, size: Tuple[int, int]) -> None:
        self.resolution.set_auto_size(size)

    def load(self, model: dict) -> None:
        self.resolution.load(model)
        self.bpp.load(model)

    def store(self, model: dict) -> None:
        self.resolution.store(model)
        self.bpp.store(model)

    def validate(self) -> bool:
        return self.resolution.validate()

    def set_enabled(self, enabled: bool) -> None:
        self.resolution.set_enabled(enabled)
        self.bpp.set_enabled(enabled)
