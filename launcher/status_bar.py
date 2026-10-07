from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from search_box import SearchBox
import ui_theme as theme

SEARCH_HINT = "Search"
SEARCH_WIDTH = 28


class StatusBar:
    def __init__(self, root: tk.Misc, on_search: Callable[[str], None]):
        bar = ttk.Frame(root, padding=(8, 6))
        bar.pack(fill="x", side="bottom")
        self._rule = tk.Frame(root, height=1, bd=0, bg=theme.SEPARATOR)
        self._rule.pack(fill="x", side="bottom")
        bar.columnconfigure(3, weight=1)

        self.search = SearchBox(bar, SEARCH_HINT, on_search, SEARCH_WIDTH)
        self.search.entry.grid(row=0, column=0, sticky="w", padx=(0, 8))

        self.update_label = ttk.Label(bar, text="", style="Hint.TLabel")
        self.update_label.grid(row=0, column=1, sticky="w")
        self.update_button = ttk.Button(bar, takefocus=False)
        self.update_button.grid(row=0, column=1, sticky="w")
        self.update_button.grid_remove()

        self._bundle_count = 0
        self.bundle_button = ttk.Button(bar, takefocus=False)
        self.bundle_button.grid(row=0, column=2, sticky="w", padx=(8, 0))
        self.bundle_button.grid_remove()

        self.status_var = tk.StringVar(value="")
        self.status_label = ttk.Label(bar, textvariable=self.status_var,
                                      anchor="e")
        self.status_label.grid(row=0, column=4, sticky="e", padx=(8, 8))
        self.progress = ttk.Progressbar(bar, orient="horizontal", length=220,
                                        mode="determinate")
        self.progress.grid(row=0, column=5, sticky="e")
        self.set_idle()

    def set_status(self, text: str) -> None:
        self.status_var.set(text)
        self.status_label.grid()

    def set_idle(self) -> None:
        self.status_var.set("")
        self.status_label.grid_remove()
        self.reset_progress()

    def set_update_status(self, text: str,
                          on_click: Optional[Callable[[], None]] = None
                          ) -> None:
        if on_click is None:
            self.update_label.config(text=text)
            self.update_button.grid_remove()
            self.update_label.grid()
            return
        self.update_button.config(text=text, command=on_click)
        self.update_label.grid_remove()
        self.update_button.grid()

    def set_bundle_updates(self, count: int,
                           on_click: Callable[[], None]) -> None:
        self.bundle_button.config(command=on_click)
        if count == self._bundle_count:
            return
        self._bundle_count = count
        if count <= 0:
            self.bundle_button.grid_remove()
            return
        self.bundle_button.config(text="Update {} ROM{}".format(
            count, "" if count == 1 else "s"))
        self.bundle_button.grid()

    def focus_search(self) -> None:
        self.search.focus()

    def retheme(self) -> None:
        self._rule.config(bg=theme.SEPARATOR)

    def show_progress(self, done: int, total: Optional[int]) -> None:
        self.progress.grid()
        if total:
            if str(self.progress.cget("mode")) != "determinate":
                self.progress.stop()
            self.progress.config(mode="determinate", maximum=total, value=done)
        else:
            if str(self.progress.cget("mode")) != "indeterminate":
                self.progress.config(mode="indeterminate")
                self.progress.start(80)

    def reset_progress(self) -> None:
        self.progress.stop()
        self.progress.config(value=0, mode="determinate")
        self.progress.grid_remove()
