from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Callable, List, Optional

from board_database import ROM_PLACING_IMX51_NAND
from board_info import board_display_name, board_storage_type, supported_boards

_SEC_NOTE = ("NAND image will be created in device directory and will take "
             "~same size as factory recovery image")


class BoardRomForm:
    def __init__(self, parent: tk.Misc, window: tk.Misc,
                 on_change: Callable[[], None],
                 name_follows_board: bool,
                 base_dir: Optional[Path] = None) -> None:
        self._window = window
        self._on_change = on_change
        self._name_follows_board = name_follows_board
        self._base_dir = base_dir
        self._prefilled_name: Optional[str] = None
        self._boards: List[dict] = list(supported_boards())

        self.frame = ttk.Frame(parent)
        self.frame.columnconfigure(1, weight=1)

        ttk.Label(self.frame, text="Board:").grid(row=0, column=0, sticky="w",
                                                  padx=(0, 8), pady=(0, 8))
        self.var_board = tk.StringVar()
        self.board_combo = ttk.Combobox(self.frame, textvariable=self.var_board,
                                        state="readonly")
        self.board_combo.grid(row=0, column=1, columnspan=2, sticky="ew",
                              pady=(0, 8))
        self.board_combo.bind("<<ComboboxSelected>>", self._on_board_changed)

        ttk.Label(self.frame, text="Name:").grid(row=1, column=0, sticky="w",
                                                 padx=(0, 8), pady=(0, 8))
        self.var_name = tk.StringVar()
        self.var_name.trace_add("write", lambda *_: self._on_change())
        self.name_entry = ttk.Entry(self.frame, textvariable=self.var_name)
        self.name_entry.grid(row=1, column=1, columnspan=2, sticky="ew",
                             pady=(0, 8))

        self.rom_label = ttk.Label(self.frame, text="")
        self.rom_label.grid(row=2, column=0, sticky="w", padx=(0, 8))
        self.var_rom = tk.StringVar()
        self.var_rom.trace_add("write", lambda *_: self._on_change())
        self.rom_entry = ttk.Entry(self.frame, textvariable=self.var_rom)
        self.rom_entry.grid(row=2, column=1, sticky="ew")
        self.browse = ttk.Button(self.frame, text="Browse…",
                                 command=self._browse)
        self.browse.grid(row=2, column=2, sticky="e", padx=(6, 0))

        self.sec_note = ttk.Label(self.frame, text=_SEC_NOTE,
                                  style="Hint.TLabel", wraplength=430,
                                  justify="left")
        self.sec_note.grid(row=3, column=1, columnspan=2, sticky="w",
                           pady=(4, 0))
        self._fill_combo()

    def select_first_board(self) -> None:
        if self._boards:
            self.board_combo.current(0)
        self._on_board_changed()

    def set_values(self, board_id: str, name: str, rom: str) -> None:
        if board_id and all(b["id"] != board_id for b in self._boards):
            self._boards.insert(0, {"id": board_id,
                                    "name": board_display_name(board_id)
                                    or board_id})
            self._fill_combo()
        for i, b in enumerate(self._boards):
            if b["id"] == board_id:
                self.board_combo.current(i)
        self.var_name.set(name)
        self.var_rom.set(rom)
        self._sync_rom_kind()

    def board_id(self) -> str:
        board = self._selected_board()
        return board["id"] if board is not None else ""

    def name(self) -> str:
        return self.var_name.get().strip()

    def rom(self) -> str:
        return self.var_rom.get().strip()

    def rom_path(self) -> Path:
        path = Path(self.rom())
        if not path.is_absolute() and self._base_dir is not None:
            path = self._base_dir / path
        return path

    def set_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.board_combo.config(state="readonly" if enabled else "disabled")
        for w in (self.name_entry, self.rom_entry, self.browse):
            w.config(state=state)

    def _fill_combo(self) -> None:
        self.board_combo.config(values=[b["name"] for b in self._boards])

    def _selected_board(self) -> Optional[dict]:
        name = self.var_board.get()
        for b in self._boards:
            if b["name"] == name:
                return b
        return None

    def _is_sec(self) -> bool:
        return board_storage_type(self.board_id()) == ROM_PLACING_IMX51_NAND

    def _sync_rom_kind(self) -> None:
        sec = self._is_sec()
        self.rom_label.config(text="Factory recovery image (.sec file):"
                              if sec else "NK/XIP/NB0/etc:")
        if sec:
            self.sec_note.grid()
        else:
            self.sec_note.grid_remove()

    def _on_board_changed(self, _event: object = None) -> None:
        board = self._selected_board()
        if board is None:
            return
        if self._name_follows_board:
            current = self.var_name.get()
            if not current.strip() or current == self._prefilled_name:
                self.var_name.set(board["name"])
            self._prefilled_name = board["name"]
        self._sync_rom_kind()
        self._on_change()

    def _browse(self) -> None:
        types = ([("Factory recovery image", "*.sec")] if self._is_sec() else
                 [("ROM images", "*.nb0 *.bin *.nb *.img *.rom *.raw"),
                  ("All files", "*.*")])
        options = {"parent": self._window, "title": "Pick your ROM file",
                   "filetypes": types}
        if self.rom() and self.rom_path().parent.is_dir():
            options["initialdir"] = str(self.rom_path().parent)
        path = filedialog.askopenfilename(**options)
        if not path:
            return
        picked = Path(path)
        if self._base_dir is not None and picked.parent == self._base_dir:
            self.var_rom.set(picked.name)
        else:
            self.var_rom.set(str(picked))
