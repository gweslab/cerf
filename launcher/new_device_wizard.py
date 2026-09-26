"""The "New" wizard: step 1 picks between creating a device from the user's
own ROM and downloading ROMs from the public repositories; step 2 is the
dynamic new-device form (board, name, ROM file, copy choice)."""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Callable, Dict, List, Optional

from board_rom_form import BoardRomForm
from cerf_user_json import resolve_device_file
from rounded_style import rounded_frame, rounded_style
from screen_geometry import fit_geometry
from ui_dialogs import show_error
from user_device_create import UserDeviceSpec, validate_device_name
import ui_theme as theme


class _PivotButton:
    """One big step-1 choice: icon on top, title, then description - the
    whole tile is clickable."""

    def __init__(self, parent: tk.Misc, icon: Optional[tk.PhotoImage],
                 title: str, description: str,
                 command: Callable[[], None]) -> None:
        self.frame = rounded_frame(parent, theme.BG_LIGHTER, theme.BORDER,
                                   theme.BG, cursor="hand2")
        inner = tk.Frame(self.frame, bg=theme.BG_LIGHTER)
        inner.place(relx=0.5, rely=0.5, anchor="center")
        widgets: List[tk.Widget] = [inner]
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
        for w in widgets + [self.frame]:
            w.bind("<Button-1>", lambda _e: command())
            w.bind("<Enter>", lambda _e: self._hover(True))
            w.bind("<Leave>", lambda _e: self._hover(False))
        self._widgets = widgets
        self._hover(False)

    def _hover(self, on: bool) -> None:
        bg = theme.BG_HOVER if on else theme.BG_LIGHTER
        self.frame.config(style=rounded_style(self.frame, bg, theme.BORDER,
                                              theme.BG))
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
        body.columnconfigure(0, weight=1)

        self.form = BoardRomForm(body, self._dlg, self._sync_create_state,
                                 name_follows_board=True)
        self.form.frame.grid(row=0, column=0, sticky="ew")

        self.var_copy = tk.BooleanVar(value=True)
        ttk.Checkbutton(body, text="Copy to device directory",
                        variable=self.var_copy).grid(
            row=1, column=0, sticky="w", pady=(8, 0))

        body.rowconfigure(2, weight=1)
        footer = ttk.Frame(body)
        footer.grid(row=3, column=0, sticky="e", pady=(12, 0))
        ttk.Button(footer, text="Back",
                   command=self._show_step1).pack(side="left", padx=(0, 6))
        self.btn_create = ttk.Button(footer, text="Create",
                                     style="Accent.TButton",
                                     command=self._create)
        self.btn_create.pack(side="left", padx=(0, 6))
        ttk.Button(footer, text="Cancel",
                   command=self._dlg.destroy).pack(side="left")

        self.form.select_first_board()

    def _sync_create_state(self) -> None:
        ok = bool(self.form.name()) and self.form.problem() is None
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
        board_id = self.form.board_id()
        if not board_id:
            return
        name = self.form.name()
        reason = validate_device_name(self._devices_dir, name)
        if reason is None:
            reason = self.form.problem()
        if reason is not None:
            show_error(self._dlg, "Cannot create device", reason)
            return
        rom_files: Dict[str, Path] = {}
        storage: Dict[str, str] = {}
        values = self.form.files()
        for ftype in self.form.file_types():
            value = values[ftype.key]
            if ftype.is_storage:
                if value and value != ftype.default_value():
                    storage[ftype.id] = value
            elif value:
                rom_files[ftype.id] = resolve_device_file(value, None)
        spec = UserDeviceSpec(name=name, board_id=board_id,
                              rom_files=rom_files, storage=storage,
                              copy_rom=self.var_copy.get())
        self._dlg.destroy()
        self._on_create(spec)
