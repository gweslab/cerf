from __future__ import annotations

import tkinter as tk

from rich_text import plain
from settings_card import SettingsColumn, switch

PAGE_EMULATOR = "emulator"


class EmulatorSettingsPage:
    key = PAGE_EMULATOR
    title = "Emulator Settings"

    def __init__(self, parent: tk.Misc) -> None:
        self.var_full_screen = tk.BooleanVar(value=False)
        self.var_detach_net = tk.BooleanVar(value=False)
        self.var_verbose = tk.BooleanVar(value=False)

        page = SettingsColumn(parent)
        self.frame = page.frame
        group = page.group()
        self._switches = []
        for title, description, var in (
                ("Borderless full screen", None, self.var_full_screen),
                ("Detach internet connection", None, self.var_detach_net),
                ("Verbose logs",
                 [plain("Resets when the launcher restarts.")],
                 self.var_verbose)):
            row = group.row(title, description)
            check = switch(row.frame, var)
            row.control(check, wide=False)
            self._switches.append(check)

    def load(self, model: dict) -> None:
        self.var_full_screen.set(bool(model.get("full_screen", False)))
        self.var_detach_net.set(not model.get("network_enabled", True))
        self.var_verbose.set(bool(model.get("verbose_logs", False)))

    def store(self, model: dict) -> None:
        model["full_screen"] = self.var_full_screen.get()
        model["network_enabled"] = not self.var_detach_net.get()
        model["verbose_logs"] = self.var_verbose.get()

    def validate(self) -> bool:
        return True

    def set_enabled(self, enabled: bool) -> None:
        for check in self._switches:
            check.config(state="normal" if enabled else "disabled")
