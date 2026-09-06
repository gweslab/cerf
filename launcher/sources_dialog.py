from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List

from bundle_repositories import (BundleRepository, read_repositories,
                                 write_repositories)
from screen_geometry import fit_geometry
from ui_dialogs import ask_text, show_info
import ui_theme as theme


class SourcesDialog:
    def __init__(self, parent: tk.Misc, on_applied: Callable[[], None]) -> None:
        self._on_applied = on_applied
        self._repos: List[BundleRepository] = read_repositories()

        dlg = tk.Toplevel(parent)
        self._dlg = dlg
        dlg.title("Bundle repositories")
        if parent.winfo_viewable():
            dlg.transient(parent)
        body = ttk.Frame(dlg, padding=8)
        body.pack(fill="both", expand=True)
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        tree = ttk.Treeview(body, columns=("url",), show="tree headings",
                            selectmode="browse")
        tree.heading("#0", text="On")
        tree.heading("url", text="Repository URL")
        tree.column("#0", width=44, minwidth=44, anchor="center", stretch=False)
        tree.column("url", width=560, minwidth=180, anchor="w", stretch=True)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb = ttk.Scrollbar(body, orient="vertical", command=tree.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        tree.configure(yscrollcommand=vsb.set)
        tree.bind("<Button-1>", self._on_click)
        tree.bind("<<TreeviewSelect>>", lambda _e: self._sync_buttons())
        self.tree = tree

        edit = ttk.Frame(body)
        edit.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self.btn_add = ttk.Button(edit, text="Add…", command=self._add)
        self.btn_add.pack(side="left")
        self.btn_del = ttk.Button(edit, text="Delete", command=self._delete,
                                  state="disabled")
        self.btn_del.pack(side="left", padx=(6, 0))

        actions = ttk.Frame(body)
        actions.grid(row=2, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(actions, text="Cancel", command=dlg.destroy).pack(
            side="left", padx=(0, 6))
        ttk.Button(actions, text="OK", command=self._ok).pack(side="left")

        self._reload_table()
        theme.apply_titlebar(dlg)
        dlg.minsize(360, 220)
        fit_geometry(dlg, 720, 380, parent=parent)
        dlg.grab_set()

    def _reload_table(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for r in self._repos:
            glyph = "☑" if r.enabled else "☐"
            self.tree.insert("", "end", iid=r.url, text=glyph,
                             values=(r.url,))
        self._sync_buttons()

    def _sync_buttons(self) -> None:
        sel = self.tree.selection()
        self.btn_del.config(state="normal" if sel else "disabled")

    def _on_click(self, event: tk.Event) -> str:
        region = self.tree.identify("region", event.x, event.y)
        iid = self.tree.identify_row(event.y)
        if not iid or region != "tree":
            return ""
        for r in self._repos:
            if r.url == iid:
                r.enabled = not r.enabled
                break
        self._reload_table()
        return "break"

    def _add(self) -> None:
        url = ask_text(self._dlg, "Add bundle repository",
                       "Bundle repository URL:")
        if not url:
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            show_info(self._dlg, "Invalid URL",
                      "Enter a full http:// or https:// repository URL.")
            return
        if any(r.url == url for r in self._repos):
            show_info(self._dlg, "Already added",
                      "That repository URL is already in the list.")
            return
        self._repos.append(BundleRepository(url=url, enabled=True))
        self._reload_table()

    def _delete(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        url = sel[0]
        self._repos = [r for r in self._repos if r.url != url]
        self._reload_table()

    def _ok(self) -> None:
        write_repositories(self._repos)
        self._dlg.destroy()
        self._on_applied()
