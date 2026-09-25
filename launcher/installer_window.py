from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Optional

from branded_dialog import SETUP_ICON_STEM, BrandedDialog, scaled
from branding import PRODUCT_NAME
from install_options import InstallOptions
from installer_download import stage_release
from installer_target import CHANGE_DIRECTORY_WARNING, default_install_dir
from sv_elements import SPLIT_DROP_STYLE, SPLIT_MAIN_STYLE
from ui_dialogs import ask_yesno, show_error
from upgrade_process import (UPGRADE_DIR_NAME, WAIT_FOR_PID_PREFIX,
                             launcher_exe_in, spawn_stage)
import ui_theme as theme


SETUP_ICO_NAME = "cerf_setup.ico"

TITLE = PRODUCT_NAME + " Setup"
HEADING = "Would you like to download and install " + PRODUCT_NAME + "?"

DESKTOP_LABEL = "Create desktop icon"
START_MENU_LABEL = "Create Start menu entry"
LAUNCH_LABEL = "Launch after installation"

UNSTABLE_LABEL = "Install unstable version"
UNSTABLE_WARNING = (
    "You picked an unstable build to install. This build might break on new "
    "updates or clobber your installation directory. If you want to continue "
    "receiving unstable channel updates, pick that channel in Settings "
    "later.\n\nWould you like to continue?")


class InstallerWindow:
    def __init__(self, root: tk.Tk) -> None:
        self._root = root
        self._queue = queue.Queue()
        self._install_dir = default_install_dir()
        self._running = False

        self._chrome = BrandedDialog(root, TITLE, HEADING,
                                     icon_stem=SETUP_ICON_STEM)
        body = self._chrome.body
        gap = scaled(root, 10)
        self._wrap = self._chrome.body_width

        self._path_label = ttk.Label(body, text=str(self._install_dir),
                                     wraplength=self._wrap, justify="left",
                                     style="Hint.TLabel")
        self._path_label.pack(anchor="w")

        self._options = ttk.Frame(body)
        self._options.pack(anchor="w", fill="x", pady=(gap, 0))
        self._desktop = self._check(DESKTOP_LABEL)
        self._start_menu = self._check(START_MENU_LABEL)
        self._launch = self._check(LAUNCH_LABEL)

        self._log: Optional[tk.Text] = None
        self._progress: Optional[ttk.Progressbar] = None

        self._change = self._chrome.add_left_button("Change Directory",
                                                    self._pick_directory)
        self._cancel = self._chrome.add_button("Cancel", self._on_cancel)
        self._more = ttk.Button(self._chrome.buttons, text="▾", width=2,
                                style=SPLIT_DROP_STYLE,
                                command=self._show_more)
        self._more.pack(side="right", padx=(1, 0))
        self._more_menu = tk.Menu(self._root, tearoff=0, bd=0,
                                  background=theme.BG_FIELD,
                                  foreground=theme.FG,
                                  activebackground=theme.BG_HOVER,
                                  activeforeground=theme.FG)
        self._more_menu.add_command(label=UNSTABLE_LABEL,
                                    command=self._start_unstable)
        self._install = self._chrome.add_button("Install", self._start,
                                                style=SPLIT_MAIN_STYLE,
                                                default=True)
        root.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._chrome.present()
        root.deiconify()
        root.lift()
        root.focus_force()

    def _check(self, label: str) -> tk.BooleanVar:
        var = tk.BooleanVar(master=self._root, value=True)
        ttk.Checkbutton(self._options, text=label, variable=var).pack(
            anchor="w")
        return var

    def _options_snapshot(self) -> InstallOptions:
        return InstallOptions(fresh=True,
                              desktop_icon=bool(self._desktop.get()),
                              start_menu=bool(self._start_menu.get()),
                              launch_after=bool(self._launch.get()))

    def _pick_directory(self) -> None:
        if not ask_yesno(self._root, "Change directory",
                         CHANGE_DIRECTORY_WARNING):
            return
        picked = filedialog.askdirectory(parent=self._root,
                                         title="Install " + PRODUCT_NAME + " to",
                                         mustexist=False)
        if not picked:
            return
        self._install_dir = Path(picked)
        self._path_label.configure(text=str(self._install_dir))

    def _on_cancel(self) -> None:
        if self._running:
            return
        self._root.quit()

    def _show_more(self) -> None:
        button = self._more
        try:
            self._more_menu.tk_popup(button.winfo_rootx(),
                                     button.winfo_rooty()
                                     + button.winfo_height())
        finally:
            self._more_menu.grab_release()

    def _start_unstable(self) -> None:
        if self._running:
            return
        if ask_yesno(self._root, UNSTABLE_LABEL, UNSTABLE_WARNING):
            self._start(unstable=True)

    def _start(self, unstable: bool = False) -> None:
        if self._running:
            return
        self._running = True
        options = self._options_snapshot()

        self._options.destroy()
        self._change.destroy()
        self._more.destroy()
        self._install.destroy()
        self._cancel.configure(state="disabled")
        self._chrome.set_heading("Downloading " + PRODUCT_NAME + "…")

        body = self._chrome.body
        self._log = tk.Text(body, height=7, width=1, wrap="char", relief="flat",
                            bg=theme.BG_FIELD, fg=theme.FG,
                            insertbackground=theme.FG, highlightthickness=1,
                            highlightbackground=theme.BORDER)
        self._log.pack(fill="both", expand=True, pady=(scaled(self._root, 10), 0))
        self._log.configure(state="disabled")

        self._progress = ttk.Progressbar(body, orient="horizontal",
                                         mode="indeterminate")
        self._progress.pack(fill="x", pady=(scaled(self._root, 10), 0))
        self._progress.start(80)
        self._chrome.present()

        threading.Thread(target=self._work, args=(options, unstable),
                         daemon=True).start()
        self._root.after(50, self._pump)

    def _work(self, options: InstallOptions, unstable: bool) -> None:
        try:
            stage_release(self._install_dir, self._post_log,
                          self._post_progress, unstable)
            staged = self._install_dir / UPGRADE_DIR_NAME
            spawn_stage(launcher_exe_in(staged),
                        [WAIT_FOR_PID_PREFIX + str(os.getpid())]
                        + options.to_arguments(), staged)
        except BaseException as exc:
            self._queue.put(("done", exc))
            return
        self._queue.put(("done", None))

    def _post_log(self, line: str) -> None:
        self._queue.put(("log", line))

    def _post_progress(self, label: str, done: int,
                       total: Optional[int]) -> None:
        self._queue.put(("progress", done, total))

    def _append(self, line: str) -> None:
        if self._log is None:
            return
        self._log.configure(state="normal")
        self._log.insert("end", line + "\n")
        self._log.see("end")
        self._log.configure(state="disabled")

    def _show_progress(self, done: int, total: Optional[int]) -> None:
        bar = self._progress
        if bar is None:
            return
        if total:
            if str(bar.cget("mode")) != "determinate":
                bar.stop()
                bar.config(mode="determinate")
            bar.config(maximum=total, value=done)
        elif str(bar.cget("mode")) != "indeterminate":
            bar.config(mode="indeterminate")
            bar.start(80)

    def _pump(self) -> None:
        try:
            while True:
                message = self._queue.get_nowait()
                if message[0] == "log":
                    self._append(message[1])
                elif message[0] == "progress":
                    self._show_progress(message[1], message[2])
                elif message[0] == "done":
                    self._finish(message[1])
                    return
        except queue.Empty:
            pass
        self._root.after(50, self._pump)

    def _finish(self, error: Optional[BaseException]) -> None:
        if self._progress is not None:
            self._progress.stop()
        if error is not None:
            show_error(self._root, TITLE,
                       "{}\n\n{} was not installed.".format(error,
                                                            PRODUCT_NAME))
        self._root.quit()
