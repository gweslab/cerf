from __future__ import annotations
from i18n import t

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Callable, Dict, List, Optional

from board_info import board_display_name, running_boards
from board_picker import BoardPicker
from board_support_label import apply_support_warning
from branded_dialog import scaled
from cerf_user_json import resolve_device_file
from device_file_types import (DeviceFileType, FileKey, device_file_types,
                               file_problem)
import glyph_images
from rich_text import plain
from settings_card import (CONTROL_GAP_DIP, SettingsColumn, path_width,
                           wrapping_label)
from sv_elements import PICKER_STYLE
import ui_theme as theme

_GAP_DIP = 6
_FILE_ROW_GAP_DIP = 10
_CHEVRON_DIP = 16

BindWheel = Callable[[tk.Misc], None]


class _FileCard:
    def __init__(self, column: SettingsColumn, title: str) -> None:
        self.group = column.group()
        self.group.row(title)
        self.body = self.group.body()
        self.body.columnconfigure(1, minsize=path_width(self.body))
        self.rows = 0
        self._widgets: List[tk.Widget] = []

    def clear(self) -> None:
        for widget in self._widgets:
            widget.destroy()
        self._widgets = []
        self.rows = 0

    def add(self, widget: tk.Widget) -> None:
        self._widgets.append(widget)

    def show(self) -> None:
        if self.rows:
            self.group.frame.grid()
        else:
            self.group.frame.grid_remove()


class BoardRomForm:
    def __init__(self, parent: tk.Misc, window: tk.Misc,
                 on_change: Callable[[], None],
                 name_follows_board: bool,
                 base_dir: Optional[Path] = None,
                 bind_wheel: Optional[BindWheel] = None) -> None:
        self._window = window
        self._on_change = on_change
        self._name_follows_board = name_follows_board
        self._base_dir = base_dir
        self._bind_wheel = bind_wheel
        self._prefilled_name: Optional[str] = None
        self._board_id = ""
        self._types: List[DeviceFileType] = []
        self._vars: Dict[FileKey, tk.StringVar] = {}
        self._inputs: List[tk.Widget] = []
        self._enabled = True

        column = SettingsColumn(parent)
        self.frame = column.frame
        ident = column.group()

        row = ident.row(t("common.name"), [
            plain(t("launcher.board_rom_form.how_the_device_reads_in_the_launcher_tree"))])
        self.var_name = tk.StringVar()
        self.var_name.trace_add("write", lambda *_: self._on_change())
        self.name_entry = ttk.Entry(row.frame, textvariable=self.var_name,
                                    width=1)
        row.control(self.name_entry)

        row = ident.row(t("common.board"), [plain(t("launcher.board_rom_form.the_type_of_device_to_emulate"))])
        self.board_button = ttk.Button(
            row.frame, style=PICKER_STYLE, compound="text", width=1,
            image=glyph_images.chevron(row.frame, scaled(row.frame, _CHEVRON_DIP),
                                       theme.FG_DIM),
            command=self._open_picker)
        row.control(self.board_button)
        self.board_warning = wrapping_label(row.frame, "")
        self.board_warning.grid(row=1, column=1, sticky="ew",
                                padx=(scaled(row.frame, CONTROL_GAP_DIP), 0),
                                pady=(scaled(row.frame, _GAP_DIP), 0))

        self._rom = _FileCard(column, t("common.rom"))
        self._storage = _FileCard(column, t("launcher.board_rom_form.storage"))
        self._show_board()

    def select_first_board(self) -> None:
        boards = running_boards()
        if boards:
            self._board_id = boards[0]["id"]
        self._on_board_changed()

    def set_values(self, board_id: str, name: str,
                   files: Dict[FileKey, str]) -> None:
        self._board_id = board_id
        self._show_board()
        self.var_name.set(name)
        for key, value in files.items():
            self._var(key, "").set(value)
        self._rebuild_files()

    def board_id(self) -> str:
        return self._board_id

    def name(self) -> str:
        return self.var_name.get().strip()

    def file_types(self) -> List[DeviceFileType]:
        return list(self._types)

    def files(self) -> Dict[FileKey, str]:
        return {t.key: self._vars[t.key].get().strip() for t in self._types}

    def problem(self) -> Optional[str]:
        if not self.board_id():
            return t("board.pick_required")
        values = self.files()
        for ftype in self._types:
            reason = file_problem(ftype, values, self._base_dir)
            if reason is not None:
                return reason
        return None

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        state = "normal" if enabled else "disabled"
        self.board_button.config(state=state)
        self.name_entry.config(state=state)
        for w in self._inputs:
            w.config(state=state)

    def _show_board(self) -> None:
        self.board_button.config(
            text=board_display_name(self._board_id) or self._board_id
            or t("launcher.board_picker.pick_a_board"))
        if apply_support_warning(self.board_warning, self._board_id):
            self.board_warning.grid()
        else:
            self.board_warning.grid_remove()

    def _open_picker(self) -> None:
        BoardPicker(self._window, self._board_id, self._on_picked)

    def _on_picked(self, board_id: str) -> None:
        self._board_id = board_id
        self._on_board_changed()

    def _var(self, key: FileKey, default: str) -> tk.StringVar:
        var = self._vars.get(key)
        if var is None:
            var = tk.StringVar(value=default)
            var.trace_add("write", lambda *_: self._on_change())
            self._vars[key] = var
        return var

    def _rebuild_files(self) -> None:
        self._rom.clear()
        self._storage.clear()
        self._inputs = []
        self._types = device_file_types(self.board_id())
        for ftype in self._types:
            self._add_file_row(self._storage if ftype.is_storage
                               else self._rom, ftype)
        self._rom.show()
        self._storage.show()
        self.set_enabled(self._enabled)
        if self._bind_wheel is not None:
            self._bind_wheel(self.frame)

    def _add_file_row(self, card: _FileCard, ftype: DeviceFileType) -> None:
        frame = card.body
        gap = scaled(frame, _GAP_DIP)
        top = scaled(frame, _FILE_ROW_GAP_DIP) if card.rows else 0
        row = card.rows
        var = self._var(ftype.key, ftype.default_value())

        label = ttk.Label(frame, text=ftype.name)
        label.grid(row=row, column=0, sticky="w", padx=(0, 2 * gap),
                   pady=(top, 0))
        block = ttk.Frame(frame)
        block.grid(row=row, column=1, sticky="ew", pady=(top, 0))
        block.columnconfigure(0, weight=1)
        entry = ttk.Entry(block, textvariable=var, width=1)
        entry.grid(row=0, column=0, sticky="ew")
        browse = ttk.Button(block, text=t("common.browse"),
                            command=lambda t=ftype: self._browse(t))
        browse.grid(row=0, column=1, padx=(gap, 0))
        card.add(label)
        card.add(block)
        self._inputs += [entry, browse]
        row += 1
        if ftype.note:
            note = wrapping_label(frame, ftype.note)
            note.grid(row=row, column=1, sticky="ew", pady=(gap // 2, 0))
            card.add(note)
            row += 1
        card.rows = row

    def _on_board_changed(self) -> None:
        self._show_board()
        name = board_display_name(self._board_id)
        if not name:
            return
        if self._name_follows_board:
            current = self.var_name.get()
            if not current.strip() or current == self._prefilled_name:
                self.var_name.set(name)
            self._prefilled_name = name
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
        types.append((t("launcher.board_rom_form.all_files"), "*.*"))
        options = {"parent": self._window, "filetypes": types}
        if current is not None and current.parent.is_dir():
            options["initialdir"] = str(current.parent)
        elif self._base_dir is not None and self._base_dir.is_dir():
            options["initialdir"] = str(self._base_dir)
        if ftype.is_storage:
            options["title"] = t('launcher.board_rom_form.pick_or_name_the_name_image', name=ftype.name)
            options["initialfile"] = (current.name if current is not None
                                      else ftype.default_value())
            options["confirmoverwrite"] = False
            if ftype.formats:
                options["defaultextension"] = "." + ftype.formats[0]
            path = filedialog.asksaveasfilename(**options)
        else:
            options["title"] = t('launcher.board_rom_form.pick_the_name', name=ftype.name)
            path = filedialog.askopenfilename(**options)
        if not path:
            return
        picked = Path(path)
        if self._base_dir is not None and picked.parent == self._base_dir:
            var.set(picked.name)
        else:
            var.set(str(picked))
