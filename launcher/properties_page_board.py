from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import Callable, Dict

from board_rom_form import BoardRomForm
from cerf_user_json import ROM_BLOCK, STORAGE_BLOCK
from device_file_types import FileKey
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
        files: Dict[FileKey, str] = {}
        for section in (ROM_BLOCK, STORAGE_BLOCK):
            for key, value in model.get(section, {}).items():
                files[(section, key)] = value
        self.form.set_values(model.get("board_id", ""), model.get("name", ""),
                             files)
        self._board_id = self.form.board_id()

    def store(self, model: dict) -> None:
        model["board_id"] = self.form.board_id()
        model["name"] = self.form.name()
        rom: Dict[str, str] = {}
        storage: Dict[str, str] = {}
        for (section, key), value in self.form.files().items():
            (storage if section == STORAGE_BLOCK else rom)[key] = value
        model["rom"] = rom
        model["storage"] = storage

    def validate(self) -> bool:
        reason = self.form.problem()
        if reason is not None:
            show_error(self._window, "Board/ROM", reason)
            return False
        return True

    def set_enabled(self, enabled: bool) -> None:
        self.form.set_enabled(enabled)

    def _on_form_changed(self) -> None:
        board_id = self.form.board_id()
        if board_id != self._board_id:
            self._board_id = board_id
            self._on_board_changed()
