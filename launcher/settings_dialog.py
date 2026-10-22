from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from app_settings import (CHANNEL_DISABLED, CHANNEL_STABLE, CHANNEL_UNSTABLE,
                          read_default_scale, read_discord_rich_presence,
                          read_update_channel, write_default_scale,
                          write_discord_rich_presence, write_update_channel)
from branded_dialog import scaled
from choice_combo import ChoiceCombo
from dialog_buttons import pack_actions
from display_scale import scale_choices, scale_label
from host_key import write_host_key
from host_key_block import HostKeyBlock
from rich_text import plain
from screen_geometry import fit_geometry
from settings_card import SettingsColumn, control_hint, switch
from ui_dialogs import show_info
import ui_theme as theme

PAGE_PAD_DIP = 14

CHANNEL_LABELS = {
    CHANNEL_DISABLED: "Disable updates",
    CHANNEL_STABLE: "Stable releases",
    CHANNEL_UNSTABLE: "Unstable releases",
}

CHANNEL_HINTS = {
    CHANNEL_DISABLED: "No update notifications.",
    CHANNEL_STABLE: "Offers each new release.",
    CHANNEL_UNSTABLE: "Offers experimental builds. They can damage your "
                      "installation or devices.",
}


class SettingsDialog:
    def __init__(self, parent: tk.Misc,
                 on_update_channel_changed: Optional[Callable[[], None]] = None,
                 owner_hwnd: int = 0) -> None:
        self._parent = parent
        self._on_channel_changed = on_update_channel_changed
        self._channel_before = read_update_channel()

        dlg = tk.Toplevel(parent)
        dlg.withdraw()
        self._dlg = dlg
        dlg.title("Settings")
        dlg.configure(bg=theme.BG)
        if parent.winfo_viewable():
            dlg.transient(parent)
        dlg.resizable(False, False)

        footer = ttk.Frame(dlg, padding=(12, 10))
        footer.pack(fill="x", side="bottom")
        tk.Frame(dlg, height=1, bg=theme.SEPARATOR).pack(fill="x", side="bottom")
        actions = ttk.Frame(footer)
        actions.pack(side="right")
        pack_actions(actions, [("OK", self._ok), ("Cancel", dlg.destroy)])

        main = ttk.Frame(dlg, style="Page.TFrame", padding=scaled(dlg, PAGE_PAD_DIP))
        main.pack(fill="both", expand=True)
        page = SettingsColumn(main)
        page.frame.pack(fill="both", expand=True)
        group = page.group()

        host_key = group.row("Host key", [
            plain("Reassign a key you use to defocus keyboard/mouse from guest")])
        self._host_key = HostKeyBlock(host_key.frame)
        host_key.control(self._host_key.frame)

        channel = group.row("Update channel", [
            plain("Choose which updates the launcher offers.")])
        channel_box = ttk.Frame(channel.frame)
        channel_box.columnconfigure(0, weight=1)
        self._channel = ChoiceCombo(channel_box, on_change=self._sync_hint)
        self._channel.widget.grid(row=0, column=0, sticky="ew")
        self._channel.set(self._channel_before)
        self._channel.configure(list(CHANNEL_LABELS), CHANNEL_LABELS.__getitem__)
        self._hint = control_hint(channel_box, max(CHANNEL_HINTS.values(), key=len))
        self._hint.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        channel.control(channel_box)

        scale = group.row("Default scale")
        self._scale = ChoiceCombo(scale.frame)
        self._scale.set(read_default_scale())
        self._scale.configure(scale_choices(), scale_label)
        scale.control(self._scale.widget)

        drp = group.row("Discord Rich Presence", [
            plain("Shows the device and OS version in your Discord profile.")])
        self.var_drp = tk.BooleanVar(value=read_discord_rich_presence())
        drp.control(switch(drp.frame, self.var_drp), wide=False)

        dlg.bind("<Escape>", lambda _e: dlg.destroy())
        dlg.update_idletasks()
        width = dlg.winfo_reqwidth()
        height = dlg.winfo_reqheight()
        self._sync_hint()

        theme.apply_titlebar(dlg)
        fit_geometry(dlg, width, height, parent=parent)
        if owner_hwnd:
            theme.set_owner_window(dlg, owner_hwnd)
        dlg.deiconify()
        dlg.lift()
        dlg.focus_force()
        dlg.grab_set()

    def wait(self) -> None:
        self._parent.wait_window(self._dlg)

    def _sync_hint(self) -> None:
        self._hint.configure(text=CHANNEL_HINTS[self._channel.get()])

    def _ok(self) -> None:
        write_discord_rich_presence(self.var_drp.get())
        write_host_key(self._host_key.value())
        write_default_scale(self._scale.get())
        channel = self._channel.get()
        write_update_channel(channel)
        self._dlg.destroy()
        show_info(self._parent, "Settings saved",
                  "Emulator settings take effect only in newly launched "
                  "instances.")
        if channel != self._channel_before and self._on_channel_changed:
            self._on_channel_changed()
