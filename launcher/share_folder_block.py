from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk

from board_database import ga_shared_folder_mount_point
from ui_dialogs import show_error, show_mount_point_help

MOUNT_POINT_MAX_CHARS = 63
_INVALID_MOUNT_CHARS = '\\/:*?"<>|'


def is_valid_mount_point_text(value: str) -> bool:
    if len(value.encode("utf-16-le")) // 2 > MOUNT_POINT_MAX_CHARS:
        return False
    return not any(c in _INVALID_MOUNT_CHARS or ord(c) < 0x20 for c in value)


class ShareFolderBlock:
    def __init__(self, parent: tk.Misc, window: tk.Misc) -> None:
        self._window = window
        self._enabled = True
        self._default_mount = ga_shared_folder_mount_point()

        self.frame = ttk.Frame(parent)
        self.frame.columnconfigure(0, weight=1)

        self.var_on = tk.BooleanVar(value=False)
        self.var_path = tk.StringVar(value="")
        self.var_mount = tk.StringVar(value=self._default_mount)
        mount_vcmd = (window.register(is_valid_mount_point_text), "%P")

        self.check = ttk.Checkbutton(self.frame, text="Share folder",
                                     variable=self.var_on,
                                     command=self._on_toggled)
        self.check.grid(row=0, column=0, columnspan=4, sticky="w")

        ttk.Label(self.frame, text="Host folder").grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Label(self.frame, text="Mount point").grid(
            row=1, column=2, sticky="w", padx=(12, 0), pady=(4, 0))
        self.help = ttk.Button(self.frame, text="?", width=2,
                               style="Help.TButton",
                               command=lambda: show_mount_point_help(window))
        self.help.grid(row=1, column=3, sticky="e", pady=(4, 0))

        self.entry = ttk.Entry(self.frame, textvariable=self.var_path)
        self.entry.grid(row=2, column=0, sticky="ew", pady=(4, 0))
        self.pick = ttk.Button(self.frame, text="Browse…",
                               command=self._on_pick)
        self.pick.grid(row=2, column=1, sticky="e", padx=(6, 0), pady=(4, 0))
        self.mount_entry = ttk.Entry(self.frame, textvariable=self.var_mount,
                                     width=14, validate="key",
                                     validatecommand=mount_vcmd)
        self.mount_entry.grid(row=2, column=2, sticky="ew", padx=(12, 0),
                              pady=(4, 0))
        self.mount_reset = ttk.Button(
            self.frame, text="Reset",
            command=lambda: self.var_mount.set(self._default_mount))
        self.mount_reset.grid(row=2, column=3, sticky="e", padx=(6, 0),
                              pady=(4, 0))
        self._refresh_state()

    def load(self, model: dict) -> None:
        path = model.get("share_folder", "")
        self.var_on.set(bool(path))
        self.var_path.set(path)
        self.var_mount.set(model.get("mount_point") or self._default_mount)
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
        model["mount_point"] = (self.var_mount.get().strip()
                                or self._default_mount)

    def validate(self) -> bool:
        mount = self.var_mount.get().strip()
        if not self.var_on.get() or is_valid_mount_point_text(mount):
            return True
        show_error(self._window, "Invalid mount point",
                   "A mount point name can have up to {} characters. It "
                   "cannot contain control characters or any of "
                   "\\ / : * ? \" < > |".format(MOUNT_POINT_MAX_CHARS))
        self.mount_entry.focus_set()
        return False

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        state = "normal" if enabled else "disabled"
        self.check.config(state=state)
        self.help.config(state=state)
        self._refresh_state()

    def _refresh_state(self) -> None:
        on = self._enabled and self.var_on.get()
        state = "normal" if on else "disabled"
        for widget in (self.entry, self.pick, self.mount_entry,
                       self.mount_reset):
            widget.config(state=state)

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
