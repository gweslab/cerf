from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from app_settings import (CHANNEL_DISABLED, CHANNEL_STABLE, CHANNEL_UNSTABLE,
                          read_discord_rich_presence, read_update_channel,
                          write_discord_rich_presence, write_update_channel)
from host_key import write_host_key
from host_key_block import HostKeyBlock
from screen_geometry import fit_geometry
from ui_dialogs import show_info
import ui_theme as theme

CHANNEL_LABELS = (
    ("Disable updates", CHANNEL_DISABLED),
    ("Stable releases", CHANNEL_STABLE),
    ("Unstable releases", CHANNEL_UNSTABLE),
)

CHANNEL_HINTS = {
    CHANNEL_DISABLED:
        "You won't be notified of any kind of new updates.",
    CHANNEL_STABLE:
        "You will be notified when a new CERF release arrives and you will "
        "receive a prompt to upgrade.",
    CHANNEL_UNSTABLE:
        "You will receive a notification and an upgrade prompt on each "
        "unfinished CERF build. These are experimental enough that they can "
        "clobber or damage the current CERF installation. Use at your own "
        "risk.",
}


class SettingsDialog:
    def __init__(self, parent: tk.Misc,
                 on_update_channel_changed: Optional[Callable[[], None]] = None,
                 owner_hwnd: int = 0) -> None:
        self._parent = parent
        self._on_channel_changed = on_update_channel_changed
        self._channel_before = read_update_channel()

        dlg = tk.Toplevel(parent)
        self._dlg = dlg
        dlg.title("Settings")
        dlg.configure(bg=theme.BG)
        if parent.winfo_viewable():
            dlg.transient(parent)
        dlg.resizable(False, False)

        body = ttk.Frame(dlg, padding=16)
        body.pack(fill="both", expand=True)

        actions = ttk.Frame(body)
        actions.pack(side="bottom", anchor="e", pady=(18, 0))
        ttk.Button(actions, text="Cancel", command=dlg.destroy).pack(
            side="left", padx=(0, 6))
        ttk.Button(actions, text="OK", command=self._ok).pack(side="left")

        ttk.Label(body, text="Host key").pack(anchor="w", pady=(0, 2))
        self._host_key = HostKeyBlock(body)

        self.var_drp = tk.BooleanVar(value=read_discord_rich_presence())
        ttk.Checkbutton(body, text="Discord Rich Presence",
                        variable=self.var_drp).pack(anchor="w", pady=(16, 0))
        ttk.Label(body, style="Hint.TLabel", wraplength=380, justify="left",
                  text="Shows the current device and OS version in your "
                       "Discord profile as an activity.").pack(
            anchor="w", pady=(2, 0))

        ttk.Label(body, text="Update channel").pack(anchor="w", pady=(16, 2))
        self._labels = [label for label, _ in CHANNEL_LABELS]
        self.var_channel = tk.StringVar(value=self._label_for(self._channel_before))
        combo = ttk.Combobox(body, state="readonly", width=30,
                             values=self._labels, textvariable=self.var_channel)
        combo.pack(anchor="w")
        combo.bind("<<ComboboxSelected>>", lambda _e: self._sync_hint())

        self._hint = ttk.Label(body, style="Hint.TLabel", wraplength=380,
                               justify="left", text="")
        self._hint.pack(anchor="w", fill="x", pady=(4, 0))

        self._hint.configure(text=max(CHANNEL_HINTS.values(), key=len))
        dlg.update_idletasks()
        height = dlg.winfo_reqheight()
        self._sync_hint()

        theme.apply_titlebar(dlg)
        fit_geometry(dlg, 440, height, parent=parent)
        if owner_hwnd:
            theme.set_owner_window(dlg, owner_hwnd)
        dlg.deiconify()
        dlg.lift()
        dlg.focus_force()
        dlg.grab_set()

    def wait(self) -> None:
        self._parent.wait_window(self._dlg)

    def _label_for(self, channel: str) -> str:
        for label, value in CHANNEL_LABELS:
            if value == channel:
                return label
        return CHANNEL_LABELS[1][0]

    def _selected_channel(self) -> str:
        picked = self.var_channel.get()
        for label, value in CHANNEL_LABELS:
            if label == picked:
                return value
        return CHANNEL_STABLE

    def _sync_hint(self) -> None:
        self._hint.configure(text=CHANNEL_HINTS[self._selected_channel()])

    def _ok(self) -> None:
        write_discord_rich_presence(self.var_drp.get())
        write_host_key(self._host_key.value())
        channel = self._selected_channel()
        write_update_channel(channel)
        self._dlg.destroy()
        show_info(self._parent, "Settings saved",
                  "Emulator settings take effect only in newly launched "
                  "instances.")
        if channel != self._channel_before and self._on_channel_changed:
            self._on_channel_changed()
