from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

from dialog_buttons import pack_actions
from properties_dialog import MODE_LIVE, PropertiesDialog
from properties_model import PropertiesModel, PropertiesSubject, reboot_keys
from properties_page_ga import PAGE_GUEST_ADDITIONS
from screen_geometry import fit_geometry
from ui_dialogs import show_error
import ui_theme as theme

RESET_NOTE = ("Some properties you changed require a soft reset to take "
              "effect. Would you like to perform it?")

_RESET_CHOICES = (("none", "Do not reset"),
                  ("soft", "Soft reset"),
                  ("hard", "Hard reset"))


class _ResetConfirmDialog:
    def __init__(self, parent: tk.Misc) -> None:
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
        self.var_reset = tk.StringVar(value="soft")
        for i, (value, label) in enumerate(_RESET_CHOICES):
            ttk.Radiobutton(body, text=label, value=value,
                            variable=self.var_reset).grid(row=1 + i, column=0,
                                                          sticky="w")
        buttons = ttk.Frame(body)
        buttons.grid(row=4, column=0, sticky="e", pady=(14, 0))
        pack_actions(buttons, [("OK", self._on_ok),
                               ("Cancel", dlg.destroy)])[0].focus_set()
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


def _ce_major(query: dict) -> Optional[int]:
    version = query.get("ce_version")
    if not isinstance(version, dict):
        return None
    major = version.get("major")
    if isinstance(major, int) and not isinstance(major, bool):
        return major
    return None


def run_live_customizations(ctx, query: dict) -> Optional[dict]:
    force = query.get("force_reboot") is True
    keys = reboot_keys(_ce_major(query))
    model = PropertiesModel(PropertiesSubject.of_device_dir(ctx.device_dir),
                            verbose_logs=False)
    model.values["guest_additions"] = True
    answer: dict = {}

    def reboot_required(values: dict) -> bool:
        return model.changed(values, keys)

    def accept(dlg: tk.Misc) -> bool:
        if force:
            choice = "soft"
        elif reboot_required(model.values):
            choice = _ResetConfirmDialog(dlg).run()
            if choice is None:
                return False
        else:
            choice = "none"
        try:
            model.save_live()
        except OSError as exc:
            show_error(dlg, "Guest Additions",
                       "Could not save:\n{}".format(exc))
            return False
        answer["reboot"] = None if choice == "none" else choice
        return True

    dialog = PropertiesDialog(ctx.root, model, MODE_LIVE,
                              PAGE_GUEST_ADDITIONS, accept, reboot_required)
    if not dialog.run(ctx.owner_hwnd):
        return None
    return answer
