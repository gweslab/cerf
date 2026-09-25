from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

import ui_theme as theme


class StatusBar:
    def __init__(self, root: tk.Misc, on_search: Callable[[], None]):
        bar = ttk.Frame(root, padding=(8, 4))
        bar.pack(fill="x", side="bottom")
        bar.columnconfigure(3, weight=1)

        self.search_link = ttk.Label(bar, text="Search", foreground=theme.LINK_FG,
                                     cursor="hand2")
        self.search_link.grid(row=0, column=0, sticky="w", padx=(0, 12))
        self.search_link.bind("<Button-1>", lambda _e: on_search())

        self.update_var = tk.StringVar(value="")
        self._update_click: Optional[Callable[[], None]] = None
        self._update_is_link = False
        self.update_link = ttk.Label(bar, textvariable=self.update_var, anchor="w")
        self.update_link.grid(row=0, column=1, sticky="w")
        self.update_link.bind("<Button-1>", self._on_update_link_click)

        self._bundle_click: Optional[Callable[[], None]] = None
        self._bundle_count = 0
        self.bundle_link = ttk.Label(bar, text="", anchor="w", cursor="hand2",
                                     foreground=theme.UPDATE_LINK)
        self.bundle_link.grid(row=0, column=2, sticky="w", padx=(12, 0))
        self.bundle_link.grid_remove()
        self.bundle_link.bind("<Button-1>", self._on_bundle_link_click)

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

    def set_update_status(self, text: str, color: str, link: bool,
                          on_click: Optional[Callable[[], None]] = None) -> None:
        self._update_click = on_click
        self._update_is_link = link
        self.update_var.set(text)
        self.update_link.config(foreground=color, cursor=("hand2" if link else ""))

    def set_bundle_updates(self, count: int,
                           on_click: Callable[[], None]) -> None:
        self._bundle_click = on_click
        if count == self._bundle_count:
            return
        self._bundle_count = count
        if count <= 0:
            self.bundle_link.grid_remove()
            return
        self.bundle_link.config(text="Update {} ROM{}".format(
            count, "" if count == 1 else "s"))
        self.bundle_link.grid()

    def retheme(self) -> None:
        self.update_link.config(
            foreground=theme.UPDATE_LINK if self._update_is_link
            else theme.FG_DIM)
        self.bundle_link.config(foreground=theme.UPDATE_LINK)
        self.search_link.config(foreground=theme.LINK_FG)

    def _on_update_link_click(self, _event: object) -> None:
        if self._update_click is not None:
            self._update_click()

    def _on_bundle_link_click(self, _event: object) -> None:
        if self._bundle_click is not None:
            self._bundle_click()

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
