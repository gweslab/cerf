from __future__ import annotations
from i18n import t

import queue
import threading
import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from app_paths import resolve_icon
from branded_dialog import SETUP_ICON_STEM, BrandedDialog, scaled
from ui_dialogs import show_dialog
import ui_theme as theme


LOG_ROWS = 12


class UpgradeWindow(tk.Toplevel):
    def __init__(self, parent: tk.Misc, heading: str,
                 on_finish: Callable[[Optional[BaseException]], None]) -> None:
        super().__init__(parent)
        self._on_finish = on_finish
        self._queue = queue.Queue()

        self.protocol("WM_DELETE_WINDOW", lambda: None)

        self._parented = bool(parent.winfo_viewable())
        if self._parented:
            self.transient(parent)
        icon = resolve_icon()
        if icon is not None:
            try:
                self.iconbitmap(str(icon))
            except tk.TclError:
                pass

        self._chrome = BrandedDialog(self, heading, heading,
                                     icon_stem=SETUP_ICON_STEM)
        body = self._chrome.body

        self.log_text = tk.Text(body, height=LOG_ROWS, width=1, wrap="char",
                                relief="flat", bg=theme.BG_FIELD, fg=theme.FG,
                                insertbackground=theme.FG,
                                highlightthickness=1,
                                highlightbackground=theme.BORDER)
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")

        self.progress = ttk.Progressbar(body, orient="horizontal",
                                        mode="indeterminate")
        self.progress.pack(fill="x", pady=(scaled(self, 10), 0))
        self.progress.start(80)

        self._chrome.present(parent if self._parented else None)
        self.grab_set()
        self.after(50, self._pump)

    def post_log(self, line: str) -> None:
        self._queue.put(("log", line))

    def post_progress(self, label: str, done: int, total: Optional[int]) -> None:
        self._queue.put(("progress", done, total))

    def post_result(self, error: Optional[BaseException]) -> None:
        self._queue.put(("result", error))

    def ask_retry(self, title: str, message: str) -> bool:
        answer = {"retry": False}
        answered = threading.Event()

        def prompt() -> None:
            answer["retry"] = show_dialog(self, title, message,
                                          ("Retry", t("common.cancel")),
                                          default=t("common.cancel")) == "Retry"
            answered.set()

        self._queue.put(("call", prompt))
        answered.wait()
        return answer["retry"]

    def _append(self, line: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _show_progress(self, done: int, total: Optional[int]) -> None:
        if total:
            if str(self.progress.cget("mode")) != "determinate":
                self.progress.stop()
                self.progress.config(mode="determinate")
            self.progress.config(maximum=total, value=done)
        elif str(self.progress.cget("mode")) != "indeterminate":
            self.progress.config(mode="indeterminate")
            self.progress.start(80)

    def _pump(self) -> None:
        try:
            while True:
                message = self._queue.get_nowait()
                kind = message[0]
                if kind == "log":
                    self._append(message[1])
                elif kind == "progress":
                    self._show_progress(message[1], message[2])
                elif kind == "call":
                    message[1]()
                elif kind == "result":
                    self.progress.stop()
                    self._on_finish(message[1])
                    return
        except queue.Empty:
            pass
        self.after(50, self._pump)
