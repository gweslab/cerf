"""Launch split-button: the "Start" button plus a boot-mode dropdown
(warm/cold) that appears only when the selected device has a saved state.img."""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Callable, List, Optional

from device_state import DeviceBundle, saved_state_info
from toolbar_overflow import MenuEntry
import ui_theme as theme


class LaunchSplitButton:
    def __init__(self, parent: tk.Misc, devices_dir: Path,
                 on_launch: Callable[[Optional[str]], None],
                 icon: object = "",
                 on_resize: Optional[Callable[[], None]] = None) -> None:
        self._devices_dir = devices_dir
        self._device: Optional[DeviceBundle] = None
        self._running = False
        self._image = icon
        self._on_launch = on_launch
        self._on_resize = on_resize
        self._dropdown = False
        self.frame = ttk.Frame(parent)
        self.btn_launch = ttk.Button(self.frame, text="Start", image=icon,
                                     compound="top",
                                     style="Toolbar.TButton",
                                     takefocus=False,
                                     command=lambda: on_launch(None))
        self.btn_launch.grid(row=0, column=0, sticky="ns")

        self._menu = tk.Menu(self.frame, tearoff=0, bd=0,
                             background=theme.BG_FIELD, foreground=theme.FG,
                             activebackground=theme.BG_HOVER,
                             activeforeground=theme.FG)
        self._menu.add_command(label="Warm boot",
                               command=lambda: on_launch("warm"))
        self._menu.add_command(label="Cold boot",
                               command=lambda: on_launch("cold"))
        self._btn_boot = ttk.Button(self.frame, text="▾", width=2,
                                     takefocus=False,
                                     style="Toolbar.TButton",
                                     command=self._popup)
        self._btn_boot.grid(row=0, column=1, sticky="ns")
        self._btn_boot.grid_remove()

        # Re-evaluate the saved-state dropdown when the launcher regains focus
        # (a snapshot may have appeared/vanished while cerf.exe ran).
        self.frame.winfo_toplevel().bind("<FocusIn>",
                                         lambda _e: self.refresh(), add="+")

    def _popup(self) -> None:
        b = self._btn_boot
        try:
            self._menu.tk_popup(b.winfo_rootx(),
                                b.winfo_rooty() + b.winfo_height())
        finally:
            self._menu.grab_release()

    def set_device(self, d: Optional[DeviceBundle]) -> None:
        self._device = d
        self.refresh()

    def set_running(self, running: bool) -> None:
        if running == self._running:
            return
        self._running = running
        self.btn_launch.config(text="Show" if running else "Start")
        self.refresh()

    def _has_saved_state(self) -> bool:
        d = self._device
        return (not self._running and d is not None and d.is_installed
                and saved_state_info(self._devices_dir / d.name) is not None)

    def menu_entries(self) -> List[MenuEntry]:
        enabled = str(self.btn_launch.cget("state")) != "disabled"
        entries = [("Show" if self._running else "Start",
                    lambda: self._on_launch(None), enabled)]
        if self._has_saved_state():
            entries.append(("Warm boot", lambda: self._on_launch("warm"), enabled))
            entries.append(("Cold boot", lambda: self._on_launch("cold"), enabled))
        return entries

    def refresh(self) -> None:
        has_state = self._has_saved_state()
        if has_state == self._dropdown:
            return
        self._dropdown = has_state
        if has_state:
            self._btn_boot.grid()
        else:
            self._btn_boot.grid_remove()
        if self._on_resize is not None:
            self._on_resize()

    def set_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.btn_launch.config(state=state)
        self._btn_boot.config(state=state)

    def retheme(self) -> None:
        self._menu.config(background=theme.BG_FIELD, foreground=theme.FG,
                          activebackground=theme.BG_HOVER,
                          activeforeground=theme.FG)
