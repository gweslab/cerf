from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Callable, Dict, List, Optional

from board_info import board_display_name, supported_boards
from cerf_user_json import resolve_device_file
from device_file_types import (DeviceFileType, FileKey, device_file_types,
                               file_problem)

_FIRST_FILE_ROW = 2


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
        self._types: List[DeviceFileType] = []
        self._vars: Dict[FileKey, tk.StringVar] = {}
        self._file_widgets: List[tk.Widget] = []
        self._inputs: List[tk.Widget] = []
        self._enabled = True

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
        self._fill_combo()

    def select_first_board(self) -> None:
        if self._boards:
            self.board_combo.current(0)
        self._on_board_changed()

    def set_values(self, board_id: str, name: str,
                   files: Dict[FileKey, str]) -> None:
        if board_id and all(b["id"] != board_id for b in self._boards):
            self._boards.insert(0, {"id": board_id,
                                    "name": board_display_name(board_id)
                                    or board_id})
            self._fill_combo()
        for i, b in enumerate(self._boards):
            if b["id"] == board_id:
                self.board_combo.current(i)
        self.var_name.set(name)
        for key, value in files.items():
            self._var(key, "").set(value)
        self._rebuild_files()

    def board_id(self) -> str:
        board = self._selected_board()
        return board["id"] if board is not None else ""

    def name(self) -> str:
        return self.var_name.get().strip()

    def file_types(self) -> List[DeviceFileType]:
        return list(self._types)

    def files(self) -> Dict[FileKey, str]:
        return {t.key: self._vars[t.key].get().strip() for t in self._types}

    def problem(self) -> Optional[str]:
        if not self.board_id():
            return "Pick a board."
        values = self.files()
        for ftype in self._types:
            reason = file_problem(ftype, values, self._base_dir)
            if reason is not None:
                return reason
        return None

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        state = "normal" if enabled else "disabled"
        self.board_combo.config(state="readonly" if enabled else "disabled")
        self.name_entry.config(state=state)
        for w in self._inputs:
            w.config(state=state)

    def _fill_combo(self) -> None:
        self.board_combo.config(values=[b["name"] for b in self._boards])

    def _selected_board(self) -> Optional[dict]:
        name = self.var_board.get()
        for b in self._boards:
            if b["name"] == name:
                return b
        return None

    def _var(self, key: FileKey, default: str) -> tk.StringVar:
        var = self._vars.get(key)
        if var is None:
            var = tk.StringVar(value=default)
            var.trace_add("write", lambda *_: self._on_change())
            self._vars[key] = var
        return var

    def _rebuild_files(self) -> None:
        for w in self._file_widgets:
            w.destroy()
        self._file_widgets = []
        self._inputs = []
        self._types = device_file_types(self.board_id())
        row = _FIRST_FILE_ROW
        for ftype in self._types:
            var = self._var(ftype.key, ftype.default_value())
            label = ttk.Label(self.frame, text=ftype.name + ":")
            label.grid(row=row, column=0, sticky="w", padx=(0, 8), pady=(0, 8))
            entry = ttk.Entry(self.frame, textvariable=var)
            entry.grid(row=row, column=1, sticky="ew", pady=(0, 8))
            browse = ttk.Button(self.frame, text="Browse…",
                                command=lambda t=ftype: self._browse(t))
            browse.grid(row=row, column=2, sticky="e", padx=(6, 0), pady=(0, 8))
            self._file_widgets += [label, entry, browse]
            self._inputs += [entry, browse]
            row += 1
            if ftype.note:
                note = ttk.Label(self.frame, text=ftype.note,
                                 style="Hint.TLabel", wraplength=1,
                                 justify="left")
                note.grid(row=row, column=1, columnspan=2, sticky="ew",
                          pady=(0, 8))
                note.bind("<Configure>",
                          lambda e, n=note: n.config(wraplength=max(1, e.width)))
                self._file_widgets.append(note)
                row += 1
        self.set_enabled(self._enabled)

    def _on_board_changed(self, _event: object = None) -> None:
        board = self._selected_board()
        if board is None:
            return
        if self._name_follows_board:
            current = self.var_name.get()
            if not current.strip() or current == self._prefilled_name:
                self.var_name.set(board["name"])
            self._prefilled_name = board["name"]
        self._rebuild_files()
        self._on_change()

    def _browse(self, ftype: DeviceFileType) -> None:
        var = self._vars[ftype.key]
        value = var.get().strip()
        current = resolve_device_file(value, self._base_dir) if value else None
        types = []
        if ftype.formats:
            types.append((ftype.name,
                          " ".join("*." + f for f in ftype.formats)))
        types.append(("All files", "*.*"))
        options = {"parent": self._window, "filetypes": types}
        if current is not None and current.parent.is_dir():
            options["initialdir"] = str(current.parent)
        elif self._base_dir is not None and self._base_dir.is_dir():
            options["initialdir"] = str(self._base_dir)
        if ftype.is_storage:
            options["title"] = "Pick or name the {} image".format(ftype.name)
            options["initialfile"] = (current.name if current is not None
                                      else ftype.default_value())
            options["confirmoverwrite"] = False
            if ftype.formats:
                options["defaultextension"] = "." + ftype.formats[0]
            path = filedialog.asksaveasfilename(**options)
        else:
            options["title"] = "Pick the {}".format(ftype.name)
            path = filedialog.askopenfilename(**options)
        if not path:
            return
        picked = Path(path)
        if self._base_dir is not None and picked.parent == self._base_dir:
            var.set(picked.name)
        else:
            var.set(str(picked))
