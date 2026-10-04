from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional

from board_info import board_ga_color_depth
from branded_dialog import scaled
from dialog_buttons import pack_actions
from properties_model import PropertiesModel
from properties_page_board import BoardRomPage, PAGE_BOARD
from properties_page_display import DisplayPage, PAGE_DISPLAY
from properties_page_emulator import EmulatorSettingsPage, PAGE_EMULATOR
from properties_page_ga import GuestAdditionsPage, PAGE_GUEST_ADDITIONS
from screen_geometry import fit_geometry
from ui_dialogs import open_device_directory
from ui_scroll import ScrollColumn
import ui_theme as theme

MODE_EDIT = "edit"
MODE_LOCKED = "locked"
MODE_LIVE = "live"

REBOOT_REQUIRED = "Reboot required"

PAGE_PAD_DIP = 14
DEFAULT_WIDTH_DIP = 900
DEFAULT_HEIGHT_DIP = 680
MIN_HEIGHT_DIP = 420

RebootCheck = Callable[[dict], bool]


class PropertiesDialog:
    def __init__(self, parent: tk.Misc, model: PropertiesModel, mode: str,
                 initial_page: str,
                 on_accept: Callable[[tk.Misc], bool],
                 reboot_required: Optional[RebootCheck] = None) -> None:
        self._parent = parent
        self._model = model
        self._subject = model.subject
        self._on_accept = on_accept
        self._reboot_required = reboot_required
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
        actions = ttk.Frame(footer)
        actions.pack(side="right")
        self._ok = pack_actions(actions, [("OK", self._on_ok),
                                          ("Cancel", self._on_cancel)])[0]
        self._reboot_label = ttk.Label(footer, text="",
                                       foreground=theme.WARN_FG)
        self._reboot_label.pack(side="right", padx=(0, 12))
        ttk.Button(footer, text="Open device directory",
                   command=lambda: open_device_directory(
                       dlg, self._subject.device_dir)).pack(side="left")

        main = ttk.Frame(dlg, style="Page.TFrame")
        main.pack(fill="both", expand=True)
        main.columnconfigure(2, weight=1)
        main.rowconfigure(0, weight=1)

        self._list = tk.Listbox(
            main, exportselection=False, activestyle="none", width=20,
            bd=0, highlightthickness=0, bg=theme.PAGE_BG, fg=theme.FG,
            selectbackground=theme.BG_SELECTED, selectforeground=theme.FG,
            font=("Segoe UI", 10))
        self._list.grid(row=0, column=0, sticky="ns",
                        pady=(scaled(dlg, PAGE_PAD_DIP), 0))
        self._list.bind("<<ListboxSelect>>", self._on_list_select)
        tk.Frame(main, width=1, bg=theme.SEPARATOR).grid(row=0, column=1,
                                                      sticky="ns")

        self._scroll = ScrollColumn(main, width=1, page=True)
        self._scroll.grid(row=0, column=2, sticky="nsew")
        area = self._scroll.inner
        pad = scaled(dlg, PAGE_PAD_DIP)

        self._board = BoardRomPage(area, dlg, self._subject.device_dir,
                                   self._on_board_changed,
                                   self._scroll.bind_wheel)
        self._ga = GuestAdditionsPage(area, dlg, self._on_ga_toggled)
        self._display = DisplayPage(area, dlg)
        self._emulator = EmulatorSettingsPage(area)
        self._pages: Dict[str, object] = {
            p.key: p for p in (self._board, self._ga, self._display,
                               self._emulator)}
        for page in self._pages.values():
            page.frame.grid(row=0, column=0, sticky="nsew", padx=pad,
                            pady=pad)
            page.frame.grid_remove()
        self._scroll.bind_wheel(area)

        dlg.bind("<Escape>", lambda _e: self._on_cancel())
        dlg.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._apply_mode(mode)
        self._keys: List[str] = []
        self._current: Optional[str] = None
        self._refresh_auto_size()
        self._initial_size()
        self._refill_list()
        if initial_page not in self._keys:
            initial_page = PAGE_BOARD
        self._show(initial_page)
        if reboot_required is not None:
            self._watch_values(area)
            self._refresh_reboot()

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
        self._scroll.scroll_to_top()
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

    def _watch_values(self, root: tk.Misc) -> None:
        names = set()
        pending = [root]
        while pending:
            widget = pending.pop()
            pending.extend(widget.winfo_children())
            for option in ("variable", "textvariable"):
                try:
                    name = str(widget.cget(option))
                except tk.TclError:
                    continue
                if name:
                    names.add(name)
        command = self._dlg.register(lambda *_args: self._refresh_reboot())
        for name in names:
            self._dlg.tk.call("trace", "add", "variable", name, "write",
                              command)

    def _refresh_reboot(self) -> None:
        values = dict(self._model.values)
        if self._current is not None:
            self._pages[self._current].store(values)
        required = self._reboot_required(values)
        self._reboot_label.config(text=REBOOT_REQUIRED if required else "")

    def _refresh_auto_size(self) -> None:
        board_id = self._model.values.get("board_id", "")
        size = self._subject.auto_size(board_id)
        self._ga.set_auto_size(size)
        self._ga.set_auto_depth(board_ga_color_depth(board_id))
        self._display.set_auto_size(size)

    def _on_board_changed(self) -> None:
        self._model.values["board_id"] = self._board.form.board_id()
        self._refresh_auto_size()
        self._refill_list()

    def _on_ga_toggled(self) -> None:
        self._model.values["guest_additions"] = self._ga.var_enabled.get()
        self._refill_list()

    def _initial_size(self) -> None:
        dlg = self._dlg
        self._board.load(self._model.values)
        for page in self._pages.values():
            page.frame.grid()
        dlg.update_idletasks()
        self._scroll.set_width(self._scroll.inner.winfo_reqwidth())
        for page in self._pages.values():
            page.frame.grid_remove()
        dlg.update_idletasks()
        dlg.minsize(dlg.winfo_reqwidth(), scaled(dlg, MIN_HEIGHT_DIP))
        fit_geometry(dlg, max(dlg.winfo_reqwidth(),
                              scaled(dlg, DEFAULT_WIDTH_DIP)),
                     scaled(dlg, DEFAULT_HEIGHT_DIP), parent=self._parent)

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
