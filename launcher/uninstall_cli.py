from __future__ import annotations

import tkinter as tk

from app_paths import exe_dir, resolve_icon
from ui_dialogs import show_dialog
from uninstall import (remove_installation, remove_shell_integration,
                       schedule_self_delete)
from uninstall_window import UninstallProgress, UninstallWindow
from upgrade_process import UpgradeError, wait_for_cerf_exit
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


def run_uninstall() -> int:
    install_dir = exe_dir()
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
        if not wait_for_cerf_exit(ask_retry):
            root.destroy()
            return 0
    except UpgradeError as exc:
        show_dialog(root, "Uninstall", str(exc))
        root.destroy()
        return 1

    progress = UninstallProgress(root)
    progress.log("Removing {}".format(install_dir))
    locked, left = remove_installation(install_dir, delete_user_data,
                                       progress.log, ask_retry)
    left += remove_shell_integration(progress.log, ask_retry)
    remove_folder = delete_user_data and not left
    if locked is not None:
        progress.log("{} {} removed after this window closes".format(
            locked.name + (" and the installation folder"
                           if remove_folder else ""),
            "are" if remove_folder else "is"))
    if left:
        progress.log("")
        progress.log("Left behind: {}".format(", ".join(left)))
        progress.finish(PARTIAL_HEADING)
    else:
        progress.finish(DONE_HEADING)
    root.mainloop()
    root.destroy()

    schedule_self_delete(locked, install_dir, remove_folder)
    return 0
