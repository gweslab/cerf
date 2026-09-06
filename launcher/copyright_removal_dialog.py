from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Optional, Tuple

import ui_theme as theme

ContactsFn = Callable[[], List[Tuple[str, Optional[str]]]]

BUTTON_LABEL = "Copyright removal"

_TITLE = "Copyright removal"
_NO_CONTACT = "-"
_COPY = "Copy"
_COPIED = "Copied"
_COPIED_MS = 1200
_WRAP = 460

_NOTICE = (
    "ROM bundles are hosted by the bundle repositories listed below. The CERF "
    "project does not host them.\n\n"
    "If you hold the copyright to a ROM, or represent the holder, and want it "
    "taken down, send a removal request to the contact address of the "
    "repository that hosts it. Requests are acted on as soon as possible and "
    "the content is deleted.\n\n"
    "Repositories added to the launcher by its user are operated by third "
    "parties and are unaffiliated with the CERF project."
)

_NO_CONTACT_HINT = (
    "- marks a repository that publishes no removal contact."
)

_NO_REPOSITORIES = "No bundle repositories are configured."


class CopyrightRemovalDialog:
    def __init__(self, parent: tk.Misc,
                 contacts: List[Tuple[str, Optional[str]]]) -> None:
        dlg = tk.Toplevel(parent)
        self._dlg = dlg
        dlg.title(_TITLE)
        dlg.configure(bg=theme.BG)
        if parent.winfo_viewable():
            dlg.transient(parent)
        dlg.resizable(False, False)

        body = ttk.Frame(dlg, padding=16)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=_NOTICE, wraplength=_WRAP, justify="left").pack(
            anchor="w", pady=(0, 12))

        if contacts:
            rows = ttk.Frame(body)
            rows.pack(fill="x")
            rows.columnconfigure(0, weight=1)
            for i, (url, email) in enumerate(contacts):
                self._add_row(rows, i, url, email)
            if any(email is None for _, email in contacts):
                ttk.Label(body, text=_NO_CONTACT_HINT, style="Hint.TLabel",
                          wraplength=_WRAP, justify="left").pack(
                    anchor="w", pady=(6, 0))
        else:
            ttk.Label(body, text=_NO_REPOSITORIES, style="Hint.TLabel").pack(
                anchor="w")

        btns = ttk.Frame(body)
        btns.pack(anchor="e", pady=(14, 0))
        close = ttk.Button(btns, text="Close", command=dlg.destroy)
        close.pack(side="left")
        close.focus_set()
        dlg.bind("<Return>", lambda _e: dlg.destroy())
        dlg.bind("<Escape>", lambda _e: dlg.destroy())

        dlg.update_idletasks()
        theme.apply_titlebar(dlg)
        w, h = dlg.winfo_reqwidth(), dlg.winfo_reqheight()
        x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        dlg.geometry(f"+{max(0, x)}+{max(0, y)}")

        dlg.grab_set()
        parent.wait_window(dlg)

    def _add_row(self, parent: tk.Misc, index: int, url: str,
                 email: Optional[str]) -> None:
        row = ttk.Frame(parent)
        row.grid(row=index, column=0, sticky="ew", pady=(0, 8))
        row.columnconfigure(0, weight=1)
        ttk.Label(row, text=url, wraplength=_WRAP, justify="left").grid(
            row=0, column=0, columnspan=2, sticky="w")

        field = tk.Entry(row, relief="flat", bg=theme.BG_FIELD, fg=theme.FG,
                         readonlybackground=theme.BG_FIELD,
                         selectbackground=theme.BG_SELECTED,
                         selectforeground=theme.FG,
                         highlightthickness=1,
                         highlightbackground=theme.BORDER,
                         highlightcolor=theme.BORDER)
        field.insert(0, email if email is not None else _NO_CONTACT)
        field.configure(state="readonly")
        field.grid(row=1, column=0, sticky="ew", pady=(2, 0), ipady=2)

        copy = ttk.Button(row, text=_COPY)
        copy.configure(command=lambda: self._copy(copy, email))
        copy.grid(row=1, column=1, sticky="w", padx=(6, 0))
        if email is None:
            copy.state(["disabled"])

    def _copy(self, button: ttk.Button, email: Optional[str]) -> None:
        if email is None:
            return
        self._dlg.clipboard_clear()
        self._dlg.clipboard_append(email)
        button.configure(text=_COPIED)
        self._dlg.after(_COPIED_MS, lambda: self._restore(button))

    def _restore(self, button: ttk.Button) -> None:
        if button.winfo_exists():
            button.configure(text=_COPY)


def show_copyright_removal(parent: tk.Misc,
                           contacts: List[Tuple[str, Optional[str]]]) -> None:
    CopyrightRemovalDialog(parent, contacts)
