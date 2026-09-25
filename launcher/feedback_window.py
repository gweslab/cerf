from __future__ import annotations

import queue
import threading
import tkinter as tk
import webbrowser
from tkinter import ttk
from typing import Dict, List

from dialog_buttons import pack_actions
from github_issues import GithubIssue, fetch_open_issues
from screen_geometry import fit_geometry
import ui_theme as theme


TITLE = "Feedback"
FEEDBACK_URL = "https://cerf.cx/feedback"
CREATE_TEXT = "Create issue"
HEADER_TEXT = ("Top-rated issues are treated as top priority and are taken "
               "into the work first. You can open your own issue, or vote on "
               "the ones already here, on GitHub.")
LOADING_TEXT = "Loading issues…"
EMPTY_TEXT = "No open issues."
BODY_PAD = 12


class FeedbackWindow:
    def __init__(self, parent: tk.Misc) -> None:
        self._issues: Dict[str, GithubIssue] = {}

        dlg = tk.Toplevel(parent)
        self._dlg = dlg
        dlg.title(TITLE)
        dlg.configure(bg=theme.BG)
        if parent.winfo_viewable():
            dlg.transient(parent)

        body = ttk.Frame(dlg, padding=BODY_PAD)
        body.pack(fill="both", expand=True)
        body.rowconfigure(1, weight=1)
        body.columnconfigure(0, weight=1)

        self._header = ttk.Label(body, text=HEADER_TEXT, wraplength=640,
                                 justify="left")
        self._header.grid(row=0, column=0, columnspan=2, sticky="w",
                          pady=(0, 10))
        body.bind("<Configure>", self._on_resize)

        tree = ttk.Treeview(body, columns=("reactions",), show="tree headings",
                            selectmode="none", cursor="hand2")
        tree.heading("#0", text="Issue", anchor="w")
        tree.heading("reactions", text="Reactions", anchor="e")
        tree.column("#0", width=300, minwidth=200, anchor="w", stretch=True)
        tree.column("reactions", width=90, minwidth=70, anchor="e",
                    stretch=False)
        tree.grid(row=1, column=0, sticky="nsew")
        tree.tag_configure("note", foreground=theme.FG_DIM)
        tree.bind("<Button-1>", self._on_click)
        self._tree = tree

        vsb = ttk.Scrollbar(body, orient="vertical", command=tree.yview)
        vsb.grid(row=1, column=1, sticky="ns")
        tree.configure(yscrollcommand=vsb.set)

        footer = ttk.Frame(body)
        footer.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        footer.columnconfigure(0, weight=1)
        actions = ttk.Frame(footer)
        actions.grid(row=0, column=0, sticky="e")
        pack_actions(actions, [
            (CREATE_TEXT, lambda: webbrowser.open(FEEDBACK_URL)),
            ("Close", dlg.destroy)])

        self._note(LOADING_TEXT)
        dlg.update_idletasks()
        theme.apply_titlebar(dlg)
        try:
            scale = max(1.0, float(dlg.winfo_fpixels("1i")) / 96.0)
        except tk.TclError:
            scale = 1.0
        dlg.minsize(int(420 * scale), int(280 * scale))
        fit_geometry(dlg, int(720 * scale), int(520 * scale), parent=parent)
        dlg.bind("<Escape>", lambda _e: dlg.destroy())
        self._start_fetch()

    def _start_fetch(self) -> None:
        outcome = queue.Queue(maxsize=1)

        def work() -> None:
            try:
                outcome.put((fetch_open_issues(), None))
            except BaseException as exc:
                outcome.put((None, exc))

        threading.Thread(target=work, daemon=True).start()

        def poll() -> None:
            if not self._dlg.winfo_exists():
                return
            try:
                issues, exc = outcome.get_nowait()
            except queue.Empty:
                self._dlg.after(50, poll)
                return
            if exc is not None:
                self._note("Could not reach GitHub.\n{}".format(exc))
            else:
                self._fill(issues or [])

        self._dlg.after(50, poll)

    def _on_resize(self, event: tk.Event) -> None:
        self._header.config(wraplength=max(240, event.width - 2 * BODY_PAD - 8))

    def _note(self, text: str) -> None:
        self._tree.delete(*self._tree.get_children())
        self._issues.clear()
        for i, line in enumerate(text.splitlines()):
            self._tree.insert("", "end", iid="note::{}".format(i), text=line,
                              values=("",), tags=("note",))

    def _fill(self, issues: List[GithubIssue]) -> None:
        self._tree.delete(*self._tree.get_children())
        self._issues.clear()
        if not issues:
            self._note(EMPTY_TEXT)
            return
        for issue in issues:
            iid = str(issue.number)
            self._issues[iid] = issue
            self._tree.insert("", "end", iid=iid,
                              text="#{}  {}".format(issue.number, issue.title),
                              values=(issue.reactions,))

    def _on_click(self, event: tk.Event) -> None:
        if self._tree.identify("region", event.x, event.y) not in ("tree",
                                                                   "cell"):
            return
        issue = self._issues.get(self._tree.identify_row(event.y))
        if issue is not None:
            webbrowser.open(issue.html_url)
