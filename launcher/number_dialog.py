from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import List, Optional, Sequence, Tuple

from branded_dialog import scaled
from dialog_buttons import pack_actions
from screen_geometry import fit_geometry
import ui_theme as theme

Field = Tuple[str, int, str]

ENTRY_CHARS = 8
MIN_WIDTH_DIP = 300


class _NumberDialog:
    def __init__(self, parent: tk.Misc, title: str, fields: Sequence[Field],
                 minimum: int) -> None:
        self._parent = parent
        self._minimum = minimum
        self.result: Optional[List[int]] = None

        dlg = tk.Toplevel(parent)
        dlg.withdraw()
        dlg.title(title)
        dlg.configure(bg=theme.BG)
        dlg.resizable(False, False)
        dlg.transient(parent)
        self._dlg = dlg

        body = ttk.Frame(dlg, padding=16)
        body.pack(fill="both", expand=True)
        digits = (dlg.register(lambda v: v == "" or v.isdigit()), "%P")
        self._vars: List[tk.StringVar] = []
        entries: List[ttk.Entry] = []
        for row, (label, initial, unit) in enumerate(fields):
            ttk.Label(body, text=label).grid(row=row, column=0, sticky="w",
                                             padx=(0, 12), pady=(0, 6))
            var = tk.StringVar(value=str(initial))
            entry = ttk.Entry(body, textvariable=var, width=ENTRY_CHARS,
                              validate="key", validatecommand=digits)
            entry.grid(row=row, column=1, sticky="w", pady=(0, 6))
            if unit:
                ttk.Label(body, text=unit).grid(row=row, column=2, sticky="w",
                                                padx=(6, 0), pady=(0, 6))
            self._vars.append(var)
            entries.append(entry)
        self._error = ttk.Label(body, text="", style="Danger.TLabel")
        self._error.grid(row=len(fields), column=0, columnspan=3, sticky="w")
        buttons = ttk.Frame(body)
        buttons.grid(row=len(fields) + 1, column=0, columnspan=3, sticky="e",
                     pady=(10, 0))
        pack_actions(buttons, [("OK", self._on_ok), ("Cancel", dlg.destroy)])
        dlg.bind("<Return>", lambda _e: self._on_ok())
        dlg.bind("<Escape>", lambda _e: dlg.destroy())
        entries[0].focus_set()
        entries[0].select_range(0, "end")

    def run(self) -> Optional[List[int]]:
        dlg = self._dlg
        previous_grab = dlg.grab_current()
        dlg.update_idletasks()
        fit_geometry(dlg, max(dlg.winfo_reqwidth(), scaled(dlg, MIN_WIDTH_DIP)),
                     dlg.winfo_reqheight(), parent=self._parent)
        theme.apply_titlebar(dlg)
        dlg.deiconify()
        dlg.grab_set()
        self._parent.wait_window(dlg)
        if previous_grab is not None and previous_grab.winfo_exists():
            previous_grab.grab_set()
        return self.result

    def _on_ok(self) -> None:
        values: List[int] = []
        for var in self._vars:
            text = var.get().strip()
            value = int(text, 10) if text else 0
            if value < self._minimum:
                self._error.config(text="Enter a whole number of {} or "
                                        "more.".format(self._minimum))
                return
            values.append(value)
        self.result = values
        self._dlg.destroy()


def ask_numbers(parent: tk.Misc, title: str, fields: Sequence[Field],
                minimum: int = 1) -> Optional[List[int]]:
    return _NumberDialog(parent, title, fields, minimum).run()
