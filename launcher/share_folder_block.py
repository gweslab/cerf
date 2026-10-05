from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk

from board_database import ga_shared_folder_mount_point
from branded_dialog import scaled
from rich_text import plain
from settings_card import SettingsGroup, control_width, switch
from ui_dialogs import show_error

MOUNT_POINT_MAX_CHARS = 63
MOUNT_PREFIX = "\\"
_INVALID_MOUNT_CHARS = '\\/:*?"<>|'
_GAP_DIP = 6


def is_valid_mount_point_text(value: str) -> bool:
    if len(value.encode("utf-16-le")) // 2 > MOUNT_POINT_MAX_CHARS:
        return False
    return not any(c in _INVALID_MOUNT_CHARS or ord(c) < 0x20 for c in value)


def _mount_name(text: str) -> str:
    if text.startswith(MOUNT_PREFIX):
        text = text[len(MOUNT_PREFIX):]
    return text


class ShareFolderBlock:
    def __init__(self, group: SettingsGroup, window: tk.Misc) -> None:
        self._window = window
        self._enabled = True
        self._default_mount = ga_shared_folder_mount_point()

        self.var_on = tk.BooleanVar(value=False)
        self.var_path = tk.StringVar(value="")
        self.var_mount = tk.StringVar(value=MOUNT_PREFIX + self._default_mount)
        self.var_mount.trace_add("write", self._keep_prefix)
        self.var_path.trace_add("write", self._on_path_changed)

        row = group.row("Share folder", [
            plain("Mount a host folder as a guest file system.")])
        self.check = switch(row.frame, self.var_on, self._on_toggled)
        row.control(self.check, wide=False)

        frame = group.body()
        gap = scaled(frame, _GAP_DIP)
        frame.columnconfigure(3, minsize=control_width(frame))
        self.entry = ttk.Entry(frame, textvariable=self.var_path, width=1)
        self.entry.grid(row=0, column=0, sticky="ew")
        self.pick = ttk.Button(frame, text="Browse…", command=self._on_pick)
        self.pick.grid(row=0, column=1, padx=(gap, 0))
        ttk.Label(frame, text="→").grid(row=0, column=2, padx=(gap, gap))
        mount = ttk.Frame(frame)
        mount.grid(row=0, column=3, sticky="ew")
        mount.columnconfigure(0, weight=1)
        name_vcmd = (window.register(
            lambda v: is_valid_mount_point_text(_mount_name(v))), "%P")
        self.mount_entry = ttk.Entry(mount, textvariable=self.var_mount,
                                     width=1, validate="key",
                                     validatecommand=name_vcmd)
        self.mount_entry.grid(row=0, column=0, sticky="ew")
        self.mount_reset = ttk.Button(
            mount, text="Reset",
            command=lambda: self.var_mount.set(
                MOUNT_PREFIX + self._default_mount))
        self.mount_reset.grid(row=0, column=1, padx=(gap, 0))
        self._refresh_state()

    def load(self, model: dict) -> None:
        path = model.get("share_folder", "")
        self.var_on.set(bool(path))
        self.var_path.set(path)
        self.var_mount.set(MOUNT_PREFIX + (model.get("mount_point")
                                           or self._default_mount))
        self._refresh_state()
        self.entry.xview_moveto(1.0)

    def store(self, model: dict) -> None:
        path = self.var_path.get().strip()
        if self.var_on.get() and path:
            model["share_folder"] = path
        else:
            model.pop("share_folder", None)
        model["mount_point"] = (_mount_name(self.var_mount.get()).strip()
                                or self._default_mount)

    def validate(self) -> bool:
        name = _mount_name(self.var_mount.get()).strip()
        if not self.var_on.get() or is_valid_mount_point_text(name):
            return True
        show_error(self._window, "Invalid mount point",
                   "A mount point name can have up to {} characters. It "
                   "cannot contain control characters or any of "
                   "\\ / : * ? \" < > |".format(MOUNT_POINT_MAX_CHARS))
        self.mount_entry.focus_set()
        return False

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self.check.config(state="normal" if enabled else "disabled")
        self._refresh_state()

    def _keep_prefix(self, *_args: object) -> None:
        text = self.var_mount.get()
        if text.startswith(MOUNT_PREFIX):
            return
        cursor = self.mount_entry.index("insert")
        self.var_mount.set(MOUNT_PREFIX + text)
        self.mount_entry.icursor(cursor + len(MOUNT_PREFIX))

    def _refresh_state(self) -> None:
        state = "normal" if self._enabled else "disabled"
        for widget in (self.entry, self.pick, self.mount_entry,
                       self.mount_reset):
            widget.config(state=state)

    def _on_path_changed(self, *_args: object) -> None:
        if not self.var_path.get().strip() and self.var_on.get():
            self.var_on.set(False)

    def _on_toggled(self) -> None:
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
            return
        self.var_path.set(picked.replace("/", "\\"))
        self.var_on.set(True)
        self.entry.xview_moveto(1.0)
