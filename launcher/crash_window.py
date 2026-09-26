from __future__ import annotations

import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import font as tkfont
from tkinter import ttk
from typing import Optional

from app_paths import install_root
from branded_dialog import load_dialog_icon
from feedback_window import FeedbackWindow
from rich_text import RichText, bold, link, plain
from screen_geometry import fit_geometry
import ui_theme as theme


TITLE = "Unexpected error - CE Runtime Foundation"
HEADING = "Something went wrong"
CRASH_LOG_NAME = "cerf.crash.log"
DEFAULT_LOG_NAME = "cerf.log"
ICON_STEM = "cerf_error"
DUMP_VIEW_LIMIT = 512 * 1024
BODY_PAD = 16
WANT_W = 680
WANT_H = 640


def _size_label(path: Optional[Path]) -> str:
    if path is None or not path.is_file():
        return "missing"
    try:
        size = path.stat().st_size
    except OSError:
        return "missing"
    if size < 1024:
        return "{} B".format(size)
    kb = (size + 1023) // 1024
    if kb < 1024:
        return "{} KB".format(kb)
    return "{:.1f} MB".format(size / (1024.0 * 1024.0))


def _locate(path: Path) -> None:
    if sys.platform != "win32":
        return
    try:
        subprocess.Popen('explorer /select,"{}"'.format(path))
    except OSError:
        pass


def _read_capped(path: Path, limit: int) -> str:
    try:
        with path.open("rb") as f:
            blob = f.read(limit + 1)
    except OSError as exc:
        return "{} could not be read: {}".format(path.name, exc)
    text = blob.decode("utf-8", errors="replace")
    if len(blob) > limit:
        text = text[:limit] + "\n\n[… truncated for display …]"
    return text


class CrashWindow:
    def __init__(self, root: tk.Tk, log_path: Optional[Path]) -> None:
        self._root = root
        here = install_root()
        self._crash_log = here / CRASH_LOG_NAME
        self._log = log_path if log_path is not None else here / DEFAULT_LOG_NAME

        root.title(TITLE)
        root.configure(bg=theme.BG)

        body = ttk.Frame(root, padding=BODY_PAD)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)

        self._build_heading(body)
        self._build_dump(body)
        self._build_links(body)
        self._build_footer(body)

        root.update_idletasks()
        root.minsize(int(WANT_W * 0.8), int(WANT_H * 0.7))
        fit_geometry(root, WANT_W, WANT_H)
        theme.apply_titlebar(root)
        root.bind("<Escape>", lambda _e: root.destroy())

    def _build_heading(self, body: ttk.Frame) -> None:
        head = ttk.Frame(body)
        head.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        self._icon = load_dialog_icon(head, ICON_STEM)
        if self._icon is not None:
            ttk.Label(head, image=self._icon).pack(side="left", padx=(0, 12))
        base = tkfont.nametofont("TkDefaultFont")
        big = base.copy()
        big.configure(size=int(abs(base.cget("size")) * 1.6), weight="bold")
        ttk.Label(head, text=HEADING, font=big).pack(side="left")

    def _build_dump(self, body: ttk.Frame) -> None:
        box = ttk.Frame(body)
        box.grid(row=1, column=0, sticky="nsew")
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)

        dump = tk.Text(box, wrap="none", relief="flat", borderwidth=0,
                       highlightthickness=1, highlightbackground=theme.BORDER,
                       highlightcolor=theme.BORDER, padx=8, pady=6,
                       background=theme.BG_FIELD, foreground=theme.FG,
                       font=tkfont.nametofont("TkFixedFont"))
        dump.grid(row=0, column=0, sticky="nsew")
        dump.insert("1.0", _read_capped(self._crash_log, DUMP_VIEW_LIMIT))
        dump.configure(state="disabled")

        vsb = ttk.Scrollbar(box, orient="vertical", command=dump.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        hsb = ttk.Scrollbar(box, orient="horizontal", command=dump.xview)
        hsb.grid(row=1, column=0, sticky="ew")
        dump.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

    def _build_links(self, body: ttk.Frame) -> None:
        RichText(body, [
            plain("If you think you have found an actual bug - "),
            link("see GitHub issues", self._open_feedback),
            plain(".  Maybe someone has already reported that - you can "
                  "upvote it."),
        ]).grid(row=2, column=0, sticky="ew", pady=(12, 10))

        cols = ttk.Frame(body)
        cols.grid(row=3, column=0, sticky="ew")
        cols.columnconfigure(1, weight=1)

        buttons = ttk.Frame(cols)
        buttons.grid(row=0, column=0, sticky="nw", padx=(0, 14))
        self._file_button(buttons, "Log", self._log)
        self._file_button(buttons, "Crash Dump", self._crash_log)

        notes = ttk.Frame(cols)
        notes.grid(row=0, column=1, sticky="ew")
        notes.columnconfigure(0, weight=1)
        RichText(notes, [
            plain("Or you can "),
            link("create your own ticket", self._open_feedback),
            plain("."),
        ]).grid(row=0, column=0, sticky="ew")
        RichText(notes, [
            plain("You must attach both log files - click to locate. Log "
                  "files might include "),
            bold("personal data"),
            plain(" like folder paths or computer specs. "),
            bold("GitHub profile is required"),
        ]).grid(row=1, column=0, sticky="ew", pady=(6, 0))

    def _file_button(self, parent: ttk.Frame, label: str, path: Path) -> None:
        text = "{} ({})".format(label, _size_label(path))
        state = "normal" if path.is_file() else "disabled"
        ttk.Button(parent, text=text, width=20, state=state,
                   command=lambda: _locate(path)).pack(fill="x", pady=(0, 6))

    def _build_footer(self, body: ttk.Frame) -> None:
        ttk.Separator(body, orient="horizontal").grid(
            row=4, column=0, sticky="ew", pady=(14, 10))
        row = ttk.Frame(body)
        row.grid(row=5, column=0, sticky="ew")
        row.columnconfigure(0, weight=1)
        exit_btn = ttk.Button(row, text="Exit", command=self._root.destroy)
        exit_btn.grid(row=0, column=1, sticky="e")
        exit_btn.focus_set()
        self._root.bind("<Return>", lambda _e: self._root.destroy())

    def _open_feedback(self) -> None:
        FeedbackWindow(self._root)
