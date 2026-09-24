from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional

from color_schemes import color_scheme_supported_for_os
from properties_model import PropertiesModel
from properties_page_board import BoardRomPage, PAGE_BOARD
from properties_page_display import DisplayPage, PAGE_DISPLAY
from properties_page_emulator import EmulatorSettingsPage, PAGE_EMULATOR
from properties_page_ga import GuestAdditionsPage, PAGE_GUEST_ADDITIONS
from screen_geometry import fit_geometry
from side_block import SideBlock
from ui_dialogs import open_device_directory
import ui_theme as theme

MODE_EDIT = "edit"
MODE_LOCKED = "locked"
MODE_LIVE = "live"


class PropertiesDialog:
    def __init__(self, parent: tk.Misc, model: PropertiesModel, mode: str,
                 initial_page: str,
                 on_accept: Callable[[tk.Misc], bool]) -> None:
        self._parent = parent
        self._model = model
        self._subject = model.subject
        self._on_accept = on_accept
        self.accepted = False

        dlg = tk.Toplevel(parent)
        dlg.withdraw()
        dlg.title("{} - Properties".format(self._subject.display_name))
        dlg.configure(bg=theme.BG)
        if parent.winfo_viewable():
            dlg.transient(parent)
        self._dlg = dlg

        footer = ttk.Frame(dlg, padding=(12, 10))
        footer.pack(fill="x", side="bottom")
        tk.Frame(dlg, height=1, bg=theme.SEPARATOR).pack(fill="x",
                                                         side="bottom")
        ttk.Button(footer, text="Cancel", command=self._on_cancel).pack(
            side="right")
        self._ok = ttk.Button(footer, text="OK", style="Accent.TButton",
                              command=self._on_ok)
        self._ok.pack(side="right", padx=(0, 6))
        ttk.Button(footer, text="Open device directory",
                   command=lambda: open_device_directory(
                       dlg, self._subject.device_dir)).pack(side="left")

        main = ttk.Frame(dlg)
        main.pack(fill="both", expand=True)
        main.columnconfigure(2, weight=1)
        main.rowconfigure(0, weight=1)

        self._list = tk.Listbox(
            main, exportselection=False, activestyle="none", width=20,
            bd=0, highlightthickness=0, bg=theme.BG_FIELD, fg=theme.FG,
            selectbackground=theme.BG_SELECTED, selectforeground=theme.FG,
            font=("Segoe UI", 10))
        self._list.grid(row=0, column=0, sticky="ns")
        self._list.bind("<<ListboxSelect>>", self._on_list_select)
        tk.Frame(main, width=1, bg=theme.SEPARATOR).grid(row=0, column=1,
                                                      sticky="ns")

        self._header = SideBlock(main, "", row=0, body_padding=(12, 10, 12, 12))
        self._header.frame.grid(row=0, column=2, sticky="nsew")
        self._header.frame.rowconfigure(1, weight=1)
        area = self._header.body
        area.grid(sticky="nsew")
        area.rowconfigure(0, weight=1)

        self._board = BoardRomPage(area, dlg, self._subject.device_dir,
                                   self._on_board_changed)
        self._ga = GuestAdditionsPage(
            area, dlg, color_scheme_supported_for_os(self._subject.os_name),
            self._on_ga_toggled)
        self._display = DisplayPage(area, dlg)
        self._emulator = EmulatorSettingsPage(area)
        self._pages: Dict[str, object] = {
            p.key: p for p in (self._board, self._ga, self._display,
                               self._emulator)}
        for page in self._pages.values():
            page.frame.grid(row=0, column=0, sticky="nsew")
            page.frame.grid_remove()

        dlg.bind("<Escape>", lambda _e: self._on_cancel())
        dlg.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._apply_mode(mode)
        self._keys: List[str] = []
        self._current: Optional[str] = None
        self._refresh_auto_size()
        self._size_to_largest_page()
        self._refill_list()
        if initial_page not in self._keys:
            initial_page = PAGE_BOARD
        self._show(initial_page)

    def run(self, owner_hwnd: int = 0) -> bool:
        dlg = self._dlg
        theme.apply_titlebar(dlg)
        if owner_hwnd:
            theme.set_owner_window(dlg, owner_hwnd)
        dlg.deiconify()
        dlg.lift()
        dlg.focus_force()
        dlg.grab_set()
        self._parent.wait_window(dlg)
        return self.accepted

    def _apply_mode(self, mode: str) -> None:
        if mode == MODE_LOCKED:
            for page in self._pages.values():
                page.set_enabled(False)
            self._ok.config(state="disabled")
        elif mode == MODE_LIVE:
            self._board.set_enabled(False)
            self._emulator.set_enabled(False)
            self._ga.lock_toggle()

    def _available(self) -> List[str]:
        values = self._model.values
        keys = [PAGE_BOARD]
        if self._subject.guest_additions_available(values.get("board_id", "")):
            keys.append(PAGE_GUEST_ADDITIONS)
        if self._subject.display_page_available(values):
            keys.append(PAGE_DISPLAY)
        keys.append(PAGE_EMULATOR)
        return keys

    def _refill_list(self) -> None:
        self._keys = self._available()
        self._list.delete(0, "end")
        for key in self._keys:
            self._list.insert("end", "  " + self._pages[key].title)
        if self._current in self._keys:
            self._list.selection_set(self._keys.index(self._current))

    def _show(self, key: str) -> None:
        page = self._pages[key]
        page.load(self._model.values)
        page.frame.grid()
        self._current = key
        self._header.set_title(page.title)
        self._list.selection_clear(0, "end")
        self._list.selection_set(self._keys.index(key))

    def _leave_current(self) -> bool:
        if self._current is None:
            return True
        page = self._pages[self._current]
        if not page.validate():
            return False
        page.store(self._model.values)
        page.frame.grid_remove()
        return True

    def _on_list_select(self, _event: object) -> None:
        picked = self._list.curselection()
        if not picked:
            return
        key = self._keys[picked[0]]
        if key == self._current:
            return
        if not self._leave_current():
            self._list.selection_clear(0, "end")
            self._list.selection_set(self._keys.index(self._current))
            return
        self._show(key)

    def _refresh_auto_size(self) -> None:
        size = self._subject.auto_size(self._model.values.get("board_id", ""))
        self._ga.set_auto_size(size)
        self._display.set_auto_size(size)

    def _on_board_changed(self) -> None:
        self._model.values["board_id"] = self._board.form.board_id()
        self._refresh_auto_size()
        self._refill_list()

    def _on_ga_toggled(self) -> None:
        self._model.values["guest_additions"] = self._ga.var_enabled.get()
        self._refill_list()

    def _size_to_largest_page(self) -> None:
        self._ga.body.grid()
        width = height = 0
        for page in self._pages.values():
            page.frame.grid()
            self._dlg.update_idletasks()
            width = max(width, self._dlg.winfo_reqwidth())
            height = max(height, self._dlg.winfo_reqheight())
            page.frame.grid_remove()
        self._ga.body.grid_remove()
        self._dlg.minsize(width, height)
        fit_geometry(self._dlg, width, height, parent=self._parent)

    def _on_ok(self) -> None:
        if not self._leave_current():
            return
        current = self._current
        self._current = None
        if self._on_accept(self._dlg):
            self.accepted = True
            self._dlg.destroy()
            return
        self._show(current)

    def _on_cancel(self) -> None:
        self._dlg.destroy()
