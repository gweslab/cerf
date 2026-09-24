from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable, List

import install_registry
import install_shortcuts
from retry_gate import RetryFn, attempt

LogFn = Callable[[str], None]

USER_DATA = ("cerf.json", "devices", "screenshots", "CF.IMG", "cerf.log",
             "cerf.crash.log")


def _keep(name: str) -> bool:
    return name.lower() in set(n.lower() for n in USER_DATA)


def _attempt(what: str, action: Callable[[], None], log: LogFn,
             ask_retry: RetryFn) -> bool:
    error = attempt("Remove failed", "Removing " + what, action, ask_retry)
    if error is not None:
        log("  {} not removed ({})".format(what, error))
    return error is None


def _remove(path: Path, log: LogFn, ask_retry: RetryFn) -> bool:
    def drop() -> None:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()

    return _attempt(path.name, drop, log, ask_retry)


def remove_installation(install_dir: Path, delete_user_data: bool,
                        log: LogFn, ask_retry: RetryFn) -> List[str]:
    left: List[str] = []
    try:
        entries = sorted(install_dir.iterdir())
    except OSError as exc:
        log("  {} cannot be read ({})".format(install_dir, exc))
        return [str(install_dir)]
    for entry in entries:
        if not delete_user_data and _keep(entry.name):
            continue
        log("  {}".format(entry.name))
        if not _remove(entry, log, ask_retry):
            left.append(entry.name)
    if delete_user_data and not left:
        if not _attempt("the installation directory", install_dir.rmdir,
                        log, ask_retry):
            left.append("the installation directory")
    return left


def remove_shell_integration(log: LogFn, ask_retry: RetryFn) -> List[str]:
    log("Removing the Start menu entries and the desktop shortcut")
    left: List[str] = []
    if not _attempt("the Start menu entries",
                    install_shortcuts.remove_start_menu_entries, log,
                    ask_retry):
        left.append("the Start menu entries")
    if not _attempt("the desktop shortcut",
                    install_shortcuts.remove_desktop_shortcut, log, ask_retry):
        left.append("the desktop shortcut")
    log("Removing the Programs and Features entry")
    if not _attempt("the Programs and Features entry",
                    install_registry.unregister, log, ask_retry):
        left.append("the Programs and Features entry")
    return left
