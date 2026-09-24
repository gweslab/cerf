from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Callable, Dict, Optional

from launch_button import LaunchSplitButton
from toolbar_overflow import OverflowBar


FEEDBACK_TEXT = "Feedback"


class Toolbar:
    def __init__(self, parent: tk.Misc, icons_dir: Optional[Path],
                 devices_dir: Path,
                 on_new: Callable[[], None],
                 on_properties: Callable[[], None],
                 on_remove_selected: Callable[[], None],
                 on_discard_selected: Callable[[], None],
                 on_launch: Callable[[Optional[str]], None],
                 on_settings: Callable[[], None],
                 on_about: Callable[[], None],
                 on_feedback: Callable[[], None]) -> None:
        self._icons_dir = icons_dir
        self._icons: Dict[str, object] = {}

        self._bar = OverflowBar(parent)
        self.frame = self._bar.frame

        self.btn_new = self._button("New", "new_device", on_new)
        self.btn_properties = self._button("Properties", "wrench",
                                           on_properties, state="disabled")
        self.btn_remove = self._button("Remove", "delete_device",
                                       on_remove_selected, state="disabled")
        self.btn_discard = self._button("Discard", "discard_state",
                                        on_discard_selected, state="disabled")
        self.start = LaunchSplitButton(self._bar.frame, devices_dir, on_launch,
                                       icon=self._icon("start_device"),
                                       on_resize=self._bar.refresh)
        self._bar.add(self.start.frame, entries=self.start.menu_entries)
        self.btn_settings = self._button("Settings", "settings", on_settings,
                                         side="right")
        self.btn_feedback = self._button(FEEDBACK_TEXT, "feedback",
                                         on_feedback, side="right")
        self.btn_about = self._button("About", "help", on_about, side="right")
        self._bar.finish()

    def _button(self, text: str, stem: str, command: Callable[[], None],
                side: str = "left", state: str = "normal") -> ttk.Button:
        btn = ttk.Button(self._bar.frame, text=text, image=self._icon(stem),
                         compound="top", command=command, state=state,
                         style="Toolbar.TButton", takefocus=False)
        self._bar.add(btn, label=lambda b=btn: str(b.cget("text")),
                      command=command, side=side,
                      enabled=lambda b=btn: str(b.cget("state")) != "disabled")
        return btn

    def _icon(self, stem: str) -> object:
        if self._icons_dir is None:
            return ""
        if stem not in self._icons:
            try:
                self._icons[stem] = tk.PhotoImage(
                    file=str(self._icons_dir / f"{stem}.png"))
            except tk.TclError:
                self._icons[stem] = ""
        return self._icons[stem]

    def retheme(self) -> None:
        self._bar.retheme()

    def set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        for b in (self.btn_new, self.btn_properties, self.btn_remove,
                  self.btn_discard):
            b.config(state=state)

    def set_selection_enabled(self, has_device: bool, can_remove: bool,
                              can_discard: bool) -> None:
        self.btn_properties.config(state="normal" if has_device
                                   else "disabled")
        self.btn_remove.config(state="normal" if can_remove else "disabled")
        self.btn_discard.config(state="normal" if can_discard else "disabled")
