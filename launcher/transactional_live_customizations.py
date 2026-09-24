from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

from properties_dialog import MODE_LIVE, PropertiesDialog
from properties_model import PropertiesModel, PropertiesSubject
from properties_page_ga import PAGE_GUEST_ADDITIONS
from screen_geometry import fit_geometry
from ui_dialogs import show_error
import ui_theme as theme

RESET_NOTE = ("Windows CE 3 and older need at least a soft reset to use the "
              "new resolution. A DPI, font-size or colour-depth change "
              "requires a reset.")

_RESET_CHOICES = (("none", "Do not reset"),
                  ("soft", "Soft reset"),
                  ("hard", "Hard reset"))


class _ResetConfirmDialog:
    def __init__(self, parent: tk.Misc, initial: str) -> None:
        self._parent = parent
        self.choice: Optional[str] = None

        dlg = tk.Toplevel(parent)
        dlg.withdraw()
        dlg.title("Reset device")
        dlg.configure(bg=theme.BG)
        dlg.resizable(False, False)
        dlg.transient(parent)
        self._dlg = dlg

        body = ttk.Frame(dlg, padding=14)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=RESET_NOTE, wraplength=380,
                  justify="left").grid(row=0, column=0, sticky="w",
                                       pady=(0, 6))
        self.var_reset = tk.StringVar(value=initial)
        for i, (value, label) in enumerate(_RESET_CHOICES):
            ttk.Radiobutton(body, text=label, value=value,
                            variable=self.var_reset).grid(row=1 + i, column=0,
                                                          sticky="w")
        buttons = ttk.Frame(body)
        buttons.grid(row=4, column=0, sticky="e", pady=(14, 0))
        ok = ttk.Button(buttons, text="OK", style="Accent.TButton",
                        command=self._on_ok)
        ok.pack(side="left")
        ttk.Button(buttons, text="Cancel", command=dlg.destroy).pack(
            side="left", padx=(6, 0))
        ok.focus_set()
        dlg.bind("<Escape>", lambda _e: dlg.destroy())

    def run(self) -> Optional[str]:
        dlg = self._dlg
        dlg.update_idletasks()
        fit_geometry(dlg, dlg.winfo_reqwidth(), dlg.winfo_reqheight(),
                     parent=self._parent)
        theme.apply_titlebar(dlg)
        dlg.deiconify()
        dlg.grab_set()
        self._parent.wait_window(dlg)
        return self.choice

    def _on_ok(self) -> None:
        self.choice = self.var_reset.get()
        self._dlg.destroy()


def run_live_customizations(ctx, query: dict) -> Optional[dict]:
    force = query.get("force_reboot") is True
    default_soft = query.get("default_reset") == "soft"
    model = PropertiesModel(PropertiesSubject.of_device_dir(ctx.device_dir),
                            verbose_logs=False)
    answer: dict = {}

    def accept(dlg: tk.Misc) -> bool:
        if force:
            choice = "soft"
        else:
            initial = ("soft" if default_soft or model.reset_needing_changed()
                       else "none")
            choice = _ResetConfirmDialog(dlg, initial).run()
            if choice is None:
                return False
        try:
            model.save_live()
        except OSError as exc:
            show_error(dlg, "Guest Additions",
                       "Could not save:\n{}".format(exc))
            return False
        answer["reboot"] = None if choice == "none" else choice
        return True

    dialog = PropertiesDialog(ctx.root, model, MODE_LIVE,
                              PAGE_GUEST_ADDITIONS, accept)
    if not dialog.run(ctx.owner_hwnd):
        return None
    return answer
