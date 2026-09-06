from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from available_update import AvailableUpdate
import ui_theme as theme


UPGRADE = "upgrade"
BROWSER = "browser"
CANCEL = "cancel"


def show_release_available(parent: tk.Misc, release: AvailableUpdate) -> str:
    dlg = tk.Toplevel(parent)
    dlg.title("A new CERF version is available")
    dlg.configure(bg=theme.BG)
    if parent.winfo_viewable():
        dlg.transient(parent)
    dlg.resizable(False, False)
    choice = {"value": CANCEL}

    body = ttk.Frame(dlg, padding=16)
    body.pack(fill="both", expand=True)

    ttk.Label(body, wraplength=520, justify="left",
              text=f"CE Runtime Foundation {release.tag} is available. "
                   f"Would you like to upgrade?").pack(anchor="w")
    ttk.Label(body, text="Last version changelog:").pack(anchor="w",
                                                         pady=(12, 4))

    changelog = ttk.Frame(body)
    changelog.pack(fill="both", expand=True)
    text = tk.Text(changelog, width=72, height=14, wrap="word", relief="flat",
                   bg=theme.BG_FIELD, fg=theme.FG, insertbackground=theme.FG,
                   highlightthickness=1, highlightbackground=theme.BORDER)
    scroll = ttk.Scrollbar(changelog, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=scroll.set)
    text.pack(side="left", fill="both", expand=True)
    scroll.pack(side="right", fill="y")
    text.insert("1.0", release.body)
    text.configure(state="disabled")

    btns = ttk.Frame(body)
    btns.pack(anchor="e", pady=(14, 0))

    def pick(value: str) -> None:
        choice["value"] = value
        dlg.destroy()

    ttk.Button(btns, text="Cancel",
               command=lambda: pick(CANCEL)).pack(side="right", padx=(6, 0))
    ttk.Button(btns, text="Open in browser",
               command=lambda: pick(BROWSER)).pack(side="right", padx=(6, 0))
    upgrade = ttk.Button(btns, text="Upgrade", style="Download.TButton",
                         command=lambda: pick(UPGRADE))
    upgrade.pack(side="right")
    upgrade.focus_set()

    dlg.bind("<Return>", lambda _e: pick(UPGRADE))
    dlg.bind("<Escape>", lambda _e: pick(CANCEL))

    dlg.update_idletasks()
    theme.apply_titlebar(dlg)
    w, h = dlg.winfo_reqwidth(), dlg.winfo_reqheight()
    x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
    dlg.geometry(f"+{max(0, x)}+{max(0, y)}")

    dlg.grab_set()
    parent.wait_window(dlg)
    return choice["value"]
