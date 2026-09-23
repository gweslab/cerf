from __future__ import annotations

import os
import shutil
import threading
import tkinter as tk
from pathlib import Path
from typing import List, Optional, Tuple

from app_paths import exe_dir, resolve_icon
from branding import PRODUCT_NAME
from install_finalize import finalize
from install_options import InstallOptions, parse_options
from ui_dialogs import show_dialog, show_error
from upgrade_install import install_upgrade
from upgrade_process import (FRESH_INSTALL_FLAG, INSTALL_FLAG,
                             POST_UPGRADE_FLAG, UPGRADE_DIR_NAME,
                             WAIT_FOR_PID_PREFIX, UpgradeError,
                             find_pid_argument, launcher_exe_in, spawn_stage,
                             stage_argument, wait_for_cerf_exit,
                             wait_for_pid_exit)
from upgrade_window import UpgradeWindow
import ui_theme as theme


NO_STAGE = "none"
INSTALL_STAGE = "install"
POST_UPGRADE_STAGE = "post-upgrade"


def parse_stage(argv: List[str]) -> Tuple[str, Optional[int]]:
    pid = find_pid_argument(argv, WAIT_FOR_PID_PREFIX)
    if POST_UPGRADE_FLAG in argv:
        return POST_UPGRADE_STAGE, pid
    if INSTALL_FLAG in argv or FRESH_INSTALL_FLAG in argv:
        return INSTALL_STAGE, pid
    return NO_STAGE, None


def _hidden_root() -> tk.Tk:
    root = tk.Tk()
    root.withdraw()
    theme.apply_theme(root)
    icon = resolve_icon()
    if icon is not None:
        try:
            root.iconbitmap(default=str(icon))
        except tk.TclError:
            pass
    return root


def _install(window: UpgradeWindow, wait_pid: Optional[int],
             upgrade_dir: Path, install_dir: Path,
             options: InstallOptions) -> None:
    try:
        if wait_pid is not None:
            window.post_log("Waiting for the previous launcher (pid %d)"
                            % wait_pid)
            wait_for_pid_exit(wait_pid)
        if not wait_for_cerf_exit(window.ask_retry):
            raise UpgradeError("cancelled while cerf.exe was running")
        install_upgrade(upgrade_dir, install_dir, window.post_log,
                        window.ask_retry)
        finalize(install_dir, options, window.post_log, window.ask_retry)
        window.post_log("Starting the installed launcher")
        spawn_stage(launcher_exe_in(install_dir),
                    stage_argument(os.getpid(), POST_UPGRADE_FLAG,
                                   options.to_arguments()), install_dir)
    except BaseException as exc:
        window.post_result(exc)
        return
    window.post_result(None)


def run_install_stage(wait_pid: Optional[int], argv: List[str]) -> int:
    root = _hidden_root()
    upgrade_dir = exe_dir()
    install_dir = upgrade_dir.parent
    options = parse_options(argv)
    status = {"code": 0}

    def finish(error: Optional[BaseException]) -> None:
        if error is not None:
            status["code"] = 1
            show_dialog(window, "%s failed" % options.verb,
                        "%s\n\nYour installation of CERF may now be "
                        "corrupted: some files were replaced and some were "
                        "not. Re-download CERF from https://cerf.cx/download"
                        % error)
        window.destroy()
        root.destroy()

    window = UpgradeWindow(root, "%s %s…" % (options.verb, PRODUCT_NAME),
                           finish)
    threading.Thread(target=_install,
                     args=(window, wait_pid, upgrade_dir, install_dir, options),
                     daemon=True).start()
    root.mainloop()
    return status["code"]


def run_post_upgrade(wait_pid: Optional[int], argv: List[str]) -> bool:
    options = parse_options(argv)
    root = _hidden_root()
    try:
        if wait_pid is not None:
            wait_for_pid_exit(wait_pid)
    except UpgradeError as exc:
        show_error(root, options.verb, str(exc))
        root.destroy()
        raise SystemExit(1)
    staged = exe_dir() / UPGRADE_DIR_NAME
    try:
        if staged.is_dir():
            shutil.rmtree(staged)
    except OSError as exc:
        show_error(root, options.verb,
                   "CERF was installed, but %s could not be removed:\n%s\n\n"
                   "Delete it by hand." % (staged, exc))
    root.destroy()
    return options.launch_after
