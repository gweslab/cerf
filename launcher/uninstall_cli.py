from __future__ import annotations

import os
import shutil
import sys
import tempfile
import tkinter as tk
from pathlib import Path
from typing import List, Optional

from app_paths import LAUNCHER_DIR_NAME, exe_dir, install_root, resolve_icon
from ui_dialogs import show_dialog
from uninstall import remove_installation, remove_shell_integration
from uninstall_window import UninstallProgress, UninstallWindow
from upgrade_process import (UNINSTALL_DIR_PREFIX, UNINSTALL_FLAG,
                             WAIT_FOR_PID_PREFIX, UpgradeError,
                             find_pid_argument, spawn_stage,
                             wait_for_cerf_exit, wait_for_pid_exit)
import ui_theme as theme


DONE_HEADING = "CE Runtime Foundation has been uninstalled"
PARTIAL_HEADING = "CE Runtime Foundation was only partly removed"


def _root() -> tk.Tk:
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


def _uninstall_dir_argument(argv: List[str]) -> Optional[Path]:
    for arg in argv:
        if arg.startswith(UNINSTALL_DIR_PREFIX):
            return Path(arg[len(UNINSTALL_DIR_PREFIX):])
    return None


def _relaunch_from_temp(install_dir: Path) -> None:
    copy_dir = Path(tempfile.mkdtemp(prefix="cerf-uninstall-"))
    launcher_dir = copy_dir / LAUNCHER_DIR_NAME
    shutil.copytree(str(exe_dir()), str(launcher_dir))
    copy = launcher_dir / Path(sys.executable).name
    spawn_stage(copy, [UNINSTALL_FLAG,
                       UNINSTALL_DIR_PREFIX + str(install_dir),
                       WAIT_FOR_PID_PREFIX + str(os.getpid())], copy_dir)


def run_uninstall(argv: List[str]) -> int:
    target = _uninstall_dir_argument(argv)
    if target is None and getattr(sys, "frozen", False):
        try:
            _relaunch_from_temp(install_root())
        except (OSError, UpgradeError) as exc:
            root = _root()
            show_dialog(root, "Uninstall",
                        "The uninstaller cannot start from the temporary "
                        "folder:\n{}".format(exc))
            root.destroy()
            return 1
        return 0

    install_dir = target if target is not None else install_root()
    wait_pid = find_pid_argument(argv, WAIT_FOR_PID_PREFIX)
    root = _root()

    confirm = UninstallWindow(root, install_dir)
    root.mainloop()
    if not confirm.accepted:
        root.destroy()
        return 0

    delete_user_data = confirm.delete_user_data

    def ask_retry(title: str, message: str) -> bool:
        return show_dialog(root, title, message, ("Retry", "Cancel"),
                           default="Cancel") == "Retry"

    try:
        if wait_pid is not None:
            wait_for_pid_exit(wait_pid)
        if not wait_for_cerf_exit(ask_retry, install_dir):
            root.destroy()
            return 0
    except UpgradeError as exc:
        show_dialog(root, "Uninstall", str(exc))
        root.destroy()
        return 1

    progress = UninstallProgress(root)
    progress.log("Removing {}".format(install_dir))
    left = remove_installation(install_dir, delete_user_data, progress.log,
                               ask_retry)
    left += remove_shell_integration(progress.log, ask_retry)
    if left:
        progress.log("")
        progress.log("Left behind: {}".format(", ".join(left)))
        progress.finish(PARTIAL_HEADING)
    else:
        progress.finish(DONE_HEADING)
    root.mainloop()
    root.destroy()
    return 0
