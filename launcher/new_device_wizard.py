"""The "New" wizard: step 1 picks between creating a device from the user's
own ROM and downloading ROMs from the public repositories; step 2 is the
dynamic new-device form (board, name, ROM file, copy choice)."""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Callable, List, Optional

from screen_geometry import fit_geometry
from board_catalog_schema import STORAGE_SEC_CONTAINER
from board_info import board_storage_type, supported_boards
from ui_dialogs import show_error
from user_device_create import UserDeviceSpec, validate_device_name
import ui_theme as theme

_SEC_NOTE = ("NAND image will be created in device directory and will take "
             "~same size as factory recovery image")


class _PivotButton:
    """One big step-1 choice: icon on top, title, then description - the
    whole tile is clickable."""

    def __init__(self, parent: tk.Misc, icon: Optional[tk.PhotoImage],
                 title: str, description: str,
                 command: Callable[[], None]) -> None:
        self.frame = tk.Frame(parent, bg=theme.BG_LIGHTER,
                              highlightthickness=1,
                              highlightbackground=theme.BORDER,
                              cursor="hand2")
        inner = tk.Frame(self.frame, bg=theme.BG_LIGHTER)
        inner.place(relx=0.5, rely=0.5, anchor="center")
        widgets: List[tk.Widget] = [self.frame, inner]
        if icon is not None:
            icon_lbl = tk.Label(inner, image=icon, bg=theme.BG_LIGHTER)
            icon_lbl.image = icon
            icon_lbl.pack(pady=(0, 10))
            widgets.append(icon_lbl)
        title_lbl = tk.Label(inner, text=title, bg=theme.BG_LIGHTER,
                             fg=theme.FG, font=("Segoe UI", 12, "bold"))
        title_lbl.pack()
        desc_lbl = tk.Label(inner, text=description, bg=theme.BG_LIGHTER,
                            fg=theme.FG_DIM, wraplength=190,
                            justify="center", font=("Segoe UI", 9))
        desc_lbl.pack(pady=(6, 0))
        widgets += [title_lbl, desc_lbl]
        for w in widgets:
            w.bind("<Button-1>", lambda _e: command())
            w.bind("<Enter>", lambda _e: self._hover(True))
            w.bind("<Leave>", lambda _e: self._hover(False))
        self._widgets = widgets

    def _hover(self, on: bool) -> None:
        bg = theme.BG_HOVER if on else theme.BG_LIGHTER
        for w in self._widgets:
            w.config(bg=bg)


class NewDeviceWizard:
    def __init__(self, parent: tk.Misc, icons_dir: Optional[Path],
                 devices_dir: Path,
                 on_download_roms: Callable[[], None],
                 on_create: Callable[[UserDeviceSpec], None]) -> None:
        self._devices_dir = devices_dir
        self._on_download_roms = on_download_roms
        self._on_create = on_create
        self._boards = supported_boards()

        dlg = tk.Toplevel(parent)
        self._dlg = dlg
        dlg.title("New")
        dlg.configure(bg=theme.BG)
        if parent.winfo_viewable():
            dlg.transient(parent)

        self._step1 = ttk.Frame(dlg, padding=12)
        self._step2 = ttk.Frame(dlg, padding=12)
        self._build_step1(icons_dir)
        self._build_step2()
        self._show_step1()

        dlg.update_idletasks()
        theme.apply_titlebar(dlg)
        fit_geometry(dlg, 560, 360, parent=parent)
        dlg.grab_set()

    def _load_icon(self, icons_dir: Optional[Path],
                   name: str) -> Optional[tk.PhotoImage]:
        if icons_dir is None:
            return None
        try:
            return tk.PhotoImage(file=str(icons_dir / name))
        except tk.TclError:
            return None

    def _build_step1(self, icons_dir: Optional[Path]) -> None:
        body = self._step1
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1, uniform="pivot")
        body.columnconfigure(1, weight=1, uniform="pivot")

        new_btn = _PivotButton(
            body, self._load_icon(icons_dir, "local_rom.png"),
            "New device", "Create a device from your local ROM",
            self._show_step2)
        new_btn.frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        dl_btn = _PivotButton(
            body, self._load_icon(icons_dir, "download.png"),
            "Download ROMs",
            "Get ready-to-run ROMs from public sources",
            self._choose_download)
        dl_btn.frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0))

        footer = ttk.Frame(body)
        footer.grid(row=1, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(footer, text="Cancel",
                   command=self._dlg.destroy).pack(side="right")

    def _build_step2(self) -> None:
        body = self._step2
        body.columnconfigure(1, weight=1)

        ttk.Label(body, text="Board:").grid(row=0, column=0, sticky="w",
                                            padx=(0, 8), pady=(0, 8))
        self.var_board = tk.StringVar()
        board_names = [b["name"] for b in self._boards]
        self.board_combo = ttk.Combobox(body, textvariable=self.var_board,
                                        state="readonly", values=board_names)
        self.board_combo.grid(row=0, column=1, columnspan=2, sticky="ew",
                              pady=(0, 8))
        self.board_combo.bind("<<ComboboxSelected>>", self._on_board_changed)

        ttk.Label(body, text="Name:").grid(row=1, column=0, sticky="w",
                                           padx=(0, 8), pady=(0, 8))
        self.var_name = tk.StringVar()
        self.var_name.trace_add("write", lambda *_: self._sync_create_state())
        ttk.Entry(body, textvariable=self.var_name).grid(
            row=1, column=1, columnspan=2, sticky="ew", pady=(0, 8))

        self.rom_label = ttk.Label(body, text="NK/XIP/NB0/etc:")
        self.rom_label.grid(row=2, column=0, sticky="w", padx=(0, 8))
        self.var_rom = tk.StringVar()
        self.var_rom.trace_add("write", lambda *_: self._sync_create_state())
        ttk.Entry(body, textvariable=self.var_rom).grid(row=2, column=1,
                                                        sticky="ew")
        ttk.Button(body, text="Browse…", command=self._browse).grid(
            row=2, column=2, sticky="e", padx=(6, 0))

        self.sec_note = ttk.Label(body, text=_SEC_NOTE, style="Hint.TLabel",
                                  wraplength=430, justify="left")
        self.sec_note.grid(row=3, column=1, columnspan=2, sticky="w",
                           pady=(4, 0))

        self.var_copy = tk.BooleanVar(value=True)
        ttk.Checkbutton(body, text="Copy to device directory",
                        variable=self.var_copy).grid(
            row=4, column=1, columnspan=2, sticky="w", pady=(8, 0))

        body.rowconfigure(5, weight=1)
        footer = ttk.Frame(body)
        footer.grid(row=6, column=0, columnspan=3, sticky="e", pady=(12, 0))
        ttk.Button(footer, text="Back",
                   command=self._show_step1).pack(side="left", padx=(0, 6))
        self.btn_create = ttk.Button(footer, text="Create",
                                     style="Accent.TButton",
                                     command=self._create)
        self.btn_create.pack(side="left", padx=(0, 6))
        ttk.Button(footer, text="Cancel",
                   command=self._dlg.destroy).pack(side="left")

        if board_names:
            self.board_combo.current(0)
        self._on_board_changed()

    def _selected_board(self) -> Optional[dict]:
        name = self.var_board.get()
        for b in self._boards:
            if b["name"] == name:
                return b
        return None

    def _on_board_changed(self, _event: object = None) -> None:
        board = self._selected_board()
        if board is None:
            return
        prev = getattr(self, "_prefilled_name", None)
        if not self.var_name.get().strip() or self.var_name.get() == prev:
            self.var_name.set(board["name"])
        self._prefilled_name = board["name"]
        sec = board_storage_type(board["board_id"]) == STORAGE_SEC_CONTAINER
        self.rom_label.config(text="Factory recovery image (.sec file):"
                              if sec else "NK/XIP/NB0/etc:")
        if sec:
            self.sec_note.grid()
        else:
            self.sec_note.grid_remove()
        self._sync_create_state()

    def _browse(self) -> None:
        board = self._selected_board()
        sec = (board is not None and
               board_storage_type(board["board_id"]) == STORAGE_SEC_CONTAINER)
        types = ([("Factory recovery image", "*.sec")] if sec else
                 [("ROM images", "*.nb0 *.bin *.nb *.img *.rom *.raw"),
                  ("All files", "*.*")])
        path = filedialog.askopenfilename(parent=self._dlg,
                                          title="Pick your ROM file",
                                          filetypes=types)
        if path:
            self.var_rom.set(path)

    def _sync_create_state(self) -> None:
        ok = bool(self.var_name.get().strip()) and \
            Path(self.var_rom.get().strip()).is_file()
        self.btn_create.config(state="normal" if ok else "disabled")

    def _show_step1(self) -> None:
        self._step2.pack_forget()
        self._step1.pack(fill="both", expand=True)

    def _show_step2(self) -> None:
        self._step1.pack_forget()
        self._step2.pack(fill="both", expand=True)
        self._sync_create_state()

    def _choose_download(self) -> None:
        self._dlg.destroy()
        self._on_download_roms()

    def _create(self) -> None:
        board = self._selected_board()
        if board is None:
            return
        name = self.var_name.get().strip()
        rom = Path(self.var_rom.get().strip())
        reason = validate_device_name(self._devices_dir, name)
        if reason is not None:
            show_error(self._dlg, "Cannot create device", reason)
            return
        if not rom.is_file():
            show_error(self._dlg, "Cannot create device",
                       f"ROM file not found:\n{rom}")
            return
        spec = UserDeviceSpec(name=name, board_id=board["board_id"],
                              rom_path=rom, copy_rom=self.var_copy.get())
        self._dlg.destroy()
        self._on_create(spec)
