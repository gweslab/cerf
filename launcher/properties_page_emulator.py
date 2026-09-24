from __future__ import annotations

import tkinter as tk
from tkinter import ttk

PAGE_EMULATOR = "emulator"


class EmulatorSettingsPage:
    key = PAGE_EMULATOR
    title = "Emulator Settings"

    def __init__(self, parent: tk.Misc) -> None:
        self.var_full_screen = tk.BooleanVar(value=False)
        self.var_detach_net = tk.BooleanVar(value=False)
        self.var_verbose = tk.BooleanVar(value=False)

        self.frame = ttk.Frame(parent)
        self.frame.columnconfigure(0, weight=1)
        self._checks = []
        for row, (text, var) in enumerate((
                ("Borderless full screen", self.var_full_screen),
                ("Detach internet connection", self.var_detach_net),
                ("Verbose logs", self.var_verbose))):
            check = ttk.Checkbutton(self.frame, text=text, variable=var)
            check.grid(row=row, column=0, sticky="w", pady=(0, 4))
            self._checks.append(check)
        ttk.Label(self.frame, text="Will be reset on next launcher restart",
                  style="Hint.TLabel").grid(row=3, column=0, sticky="w",
                                            padx=(22, 0))

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
        for check in self._checks:
            check.config(state="normal" if enabled else "disabled")
