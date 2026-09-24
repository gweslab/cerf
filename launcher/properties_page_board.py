from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import Callable

from board_rom_form import BoardRomForm
from ui_dialogs import show_error

PAGE_BOARD = "board"


class BoardRomPage:
    key = PAGE_BOARD
    title = "Board/ROM"

    def __init__(self, parent: tk.Misc, window: tk.Misc, device_dir: Path,
                 on_board_changed: Callable[[], None]) -> None:
        self._window = window
        self._on_board_changed = on_board_changed
        self._board_id = ""
        self.form = BoardRomForm(parent, window, self._on_form_changed,
                                 name_follows_board=False, base_dir=device_dir)
        self.frame = self.form.frame

    def load(self, model: dict) -> None:
        self.form.set_values(model.get("board_id", ""), model.get("name", ""),
                             model.get("rom_primary", ""))
        self._board_id = self.form.board_id()

    def store(self, model: dict) -> None:
        model["board_id"] = self.form.board_id()
        model["name"] = self.form.name()
        model["rom_primary"] = self.form.rom()

    def validate(self) -> bool:
        if not self.form.board_id():
            show_error(self._window, "Board", "Pick a board.")
            return False
        if not self.form.rom_path().is_file():
            show_error(self._window, "ROM file",
                       "ROM file not found:\n{}".format(self.form.rom_path()))
            self.form.rom_entry.focus_set()
            return False
        return True

    def set_enabled(self, enabled: bool) -> None:
        self.form.set_enabled(enabled)

    def _on_form_changed(self) -> None:
        board_id = self.form.board_id()
        if board_id != self._board_id:
            self._board_id = board_id
            self._on_board_changed()
