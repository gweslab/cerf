from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import List, Set

from host_key import (DEFAULT_HOST_KEY, MAX_HOST_KEY_LEN, VK_ESCAPE,
                      combo_label, read_host_key, vk_from_tk_event)

PROMPT = "Press the new host key..."


class HostKeyBlock:
    def __init__(self, parent: tk.Misc) -> None:
        self._vks: List[int] = read_host_key()
        self._pending: List[int] = []
        self._held: Set[int] = set()
        self._capturing = False

        row = ttk.Frame(parent)
        row.pack(anchor="w", fill="x")

        self._button = ttk.Button(row, width=30, text=combo_label(self._vks),
                                  command=self._begin_capture)
        self._button.pack(side="left")
        ttk.Button(row, text="Reset", command=self._reset).pack(
            side="left", padx=(6, 0))

        self._button.bind("<KeyPress>", self._on_key_press)
        self._button.bind("<KeyRelease>", self._on_key_release)
        self._button.bind("<FocusOut>", lambda _e: self._end_capture(False))

    def value(self) -> List[int]:
        return list(self._vks)

    def _begin_capture(self) -> None:
        if self._capturing:
            self._end_capture(False)
            return
        self._capturing = True
        self._pending = []
        self._held = set()
        self._button.configure(text=PROMPT)
        self._button.focus_set()

    def _end_capture(self, commit: bool) -> None:
        if not self._capturing:
            return
        if commit and self._pending and self._pending != [VK_ESCAPE]:
            self._vks = list(self._pending)
        self._capturing = False
        self._pending = []
        self._held = set()
        self._button.configure(text=combo_label(self._vks))

    def _reset(self) -> None:
        self._end_capture(False)
        self._vks = list(DEFAULT_HOST_KEY)
        self._button.configure(text=combo_label(self._vks))

    def _on_key_press(self, event) -> str:
        if not self._capturing:
            return ""
        vk = vk_from_tk_event(event)
        if vk:
            self._held.add(vk)
            if vk not in self._pending and len(self._pending) < MAX_HOST_KEY_LEN:
                self._pending.append(vk)
                self._button.configure(text=combo_label(self._pending))
        return "break"

    def _on_key_release(self, event) -> str:
        if not self._capturing:
            return ""
        self._held.discard(vk_from_tk_event(event))
        if not self._held:
            self._end_capture(True)
        return "break"
