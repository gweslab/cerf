from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk


class ShareFolderBlock:
    def __init__(self, parent: tk.Misc, window: tk.Misc) -> None:
        self._window = window
        self._enabled = True

        self.frame = ttk.Frame(parent)
        self.frame.columnconfigure(0, weight=1)

        self.var_on = tk.BooleanVar(value=False)
        self.var_path = tk.StringVar(value="")

        self.check = ttk.Checkbutton(self.frame, text="Share folder",
                                     variable=self.var_on,
                                     command=self._on_toggled)
        self.check.grid(row=0, column=0, columnspan=2, sticky="w")
        self.entry = ttk.Entry(self.frame, textvariable=self.var_path)
        self.entry.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        self.pick = ttk.Button(self.frame, text="Browse…",
                               command=self._on_pick)
        self.pick.grid(row=1, column=1, sticky="e", padx=(6, 0), pady=(4, 0))
        self._refresh_state()

    def load(self, model: dict) -> None:
        path = model.get("share_folder", "")
        self.var_on.set(bool(path))
        self.var_path.set(path)
        try:
            self.entry.xview_moveto(1.0)
        except tk.TclError:
            pass
        self._refresh_state()

    def store(self, model: dict) -> None:
        path = self.var_path.get().strip()
        if self.var_on.get() and path:
            model["share_folder"] = path
        else:
            model.pop("share_folder", None)

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self.check.config(state="normal" if enabled else "disabled")
        self._refresh_state()

    def _refresh_state(self) -> None:
        on = self._enabled and self.var_on.get()
        state = "normal" if on else "disabled"
        self.entry.config(state=state)
        self.pick.config(state=state)

    def _on_toggled(self) -> None:
        self._refresh_state()
        if self.var_on.get() and not self.var_path.get().strip():
            self._on_pick()

    def _on_pick(self) -> None:
        options = {"parent": self._window, "mustexist": True,
                   "title": "Choose a host folder to share with the guest"}
        initial = self.var_path.get().strip()
        if initial:
            options["initialdir"] = initial
        picked = filedialog.askdirectory(**options)
        if not picked:
            if not self.var_path.get().strip():
                self.var_on.set(False)
                self._refresh_state()
            return
        self.var_path.set(picked.replace("/", "\\"))
        self.entry.xview_moveto(1.0)
