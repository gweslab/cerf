from __future__ import annotations
from i18n import t

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from app_settings import (CHANNEL_DISABLED, CHANNEL_STABLE, CHANNEL_UNSTABLE,
                          read_discord_rich_presence, read_update_channel,
                          write_discord_rich_presence, write_update_channel,
                          read_language, write_language)
from i18n import available_languages, set_language
from dialog_buttons import pack_actions
from host_key import write_host_key
from host_key_block import HostKeyBlock
from screen_geometry import fit_geometry
from ui_dialogs import show_info
import ui_theme as theme

CHANNEL_LABELS = (
    ("settings.updates_disabled", CHANNEL_DISABLED),
    ("settings.updates_stable", CHANNEL_STABLE),
    ("settings.updates_unstable", CHANNEL_UNSTABLE),
)

CHANNEL_HINTS = {
    CHANNEL_DISABLED:
        "settings.updates_disabled_hint",
    CHANNEL_STABLE:
        "settings.updates_stable_hint",
    CHANNEL_UNSTABLE:
        "settings.updates_unstable_hint",
}


class SettingsDialog:
    def __init__(self, parent: tk.Misc,
                 on_update_channel_changed: Optional[Callable[[], None]] = None,
                 on_language_changed: Optional[Callable[[], None]] = None,
                 owner_hwnd: int = 0) -> None:
        self._parent = parent
        self._on_channel_changed = on_update_channel_changed
        self._channel_before = read_update_channel()
        self._on_language_changed = on_language_changed
        self._language_before = read_language()
        self._languages = available_languages()

        dlg = tk.Toplevel(parent)
        self._dlg = dlg
        dlg.title(t("common.settings"))
        dlg.configure(bg=theme.BG)
        if parent.winfo_viewable():
            dlg.transient(parent)
        dlg.resizable(False, False)

        body = ttk.Frame(dlg, padding=16)
        body.pack(fill="both", expand=True)

        actions = ttk.Frame(body)
        actions.pack(side="bottom", anchor="e", pady=(18, 0))
        pack_actions(actions, [(t("common.ok"), self._ok), (t("common.cancel"), dlg.destroy)])

        ttk.Label(body, text=t("settings.host_key")).pack(anchor="w", pady=(0, 2))
        self._host_key = HostKeyBlock(body)

        ttk.Label(body, text=t("settings.language")).pack(anchor="w", pady=(16, 2))
        self._language_combo = ttk.Combobox(body, state="readonly", width=30,
                                           values=[name for _, name in self._languages])
        self._language_combo.pack(anchor="w")
        for index, (code, _) in enumerate(self._languages):
            if code == self._language_before:
                self._language_combo.current(index)
                break

        self.var_drp = tk.BooleanVar(value=read_discord_rich_presence())
        ttk.Checkbutton(body, text=t("settings.discord_rich_presence"),
                        variable=self.var_drp).pack(anchor="w", pady=(16, 0))
        ttk.Label(body, style="Hint.TLabel", wraplength=380, justify="left",
                  text=t("settings.shows_the_current_device_and_os_version_in_your")).pack(
            anchor="w", pady=(2, 0))

        ttk.Label(body, text=t("settings.update_channel")).pack(anchor="w", pady=(16, 2))
        self._labels = [t(label) for label, _ in CHANNEL_LABELS]
        self.var_channel = tk.StringVar(value=self._label_for(self._channel_before))
        combo = ttk.Combobox(body, state="readonly", width=30,
                             values=self._labels, textvariable=self.var_channel)
        self._channel_combo = combo
        combo.pack(anchor="w")
        combo.bind("<<ComboboxSelected>>", lambda _e: self._sync_hint())

        self._hint = ttk.Label(body, style="Hint.TLabel", wraplength=380,
                               justify="left", text="")
        self._hint.pack(anchor="w", fill="x", pady=(4, 0))

        self._hint.configure(text=max((t(key) for key in CHANNEL_HINTS.values()), key=len))
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
                return t(label)
        return t(CHANNEL_LABELS[1][0])

    def _selected_channel(self) -> str:
        index = self._channel_combo.current()
        if index >= 0:
            return CHANNEL_LABELS[index][1]
        return CHANNEL_STABLE

    def _sync_hint(self) -> None:
        self._hint.configure(text=t(CHANNEL_HINTS[self._selected_channel()]))

    def _ok(self) -> None:
        write_discord_rich_presence(self.var_drp.get())
        write_host_key(self._host_key.value())
        channel = self._selected_channel()
        write_update_channel(channel)
        index = self._language_combo.current()
        language = self._languages[index][0] if index >= 0 else self._language_before
        language_changed = language != self._language_before
        if language_changed:
            set_language(language)
            write_language(language)
        self._dlg.destroy()
        if language_changed and self._on_language_changed:
            self._on_language_changed()
        show_info(self._parent, t("settings.settings_saved"),
                  t("settings.emulator_settings_take_effect_only_in_newly_launched_instances"))
        if channel != self._channel_before and self._on_channel_changed:
            self._on_channel_changed()
