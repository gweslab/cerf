from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import install_registry
import install_shortcuts
from retry_gate import RetryFn, attempt

LogFn = Callable[[str], None]

USER_DATA = ("cerf.json", "devices", "screenshots", "CF.IMG", "cerf.log",
             "cerf.crash.log")

SELF_DELETE_ATTEMPTS = 60


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
                        log: LogFn,
                        ask_retry: RetryFn) -> Tuple[Optional[Path],
                                                     List[str]]:
    own = Path(sys.executable).resolve() if getattr(sys, "frozen", False) \
        else None
    locked: Optional[Path] = None
    left: List[str] = []
    try:
        entries = sorted(install_dir.iterdir())
    except OSError as exc:
        log("  {} cannot be read ({})".format(install_dir, exc))
        return None, [str(install_dir)]
    for entry in entries:
        if not delete_user_data and _keep(entry.name):
            continue
        try:
            is_own = own is not None and entry.resolve() == own
        except OSError:
            is_own = False
        if is_own:
            locked = entry
            continue
        log("  {}".format(entry.name))
        if not _remove(entry, log, ask_retry):
            left.append(entry.name)
    if delete_user_data and locked is None and not left:
        if not _attempt("the installation directory", install_dir.rmdir,
                        log, ask_retry):
            left.append("the installation directory")
    return locked, left


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


def _self_delete_script() -> str:
    return "\r\n".join([
        "@echo off",
        "for /L %%N in (1,1,{}) do (".format(SELF_DELETE_ATTEMPTS),
        '  if not exist "%~1" goto folder',
        '  del /F /Q "%~1" >nul 2>&1',
        "  ping -n 2 127.0.0.1 >nul",
        ")",
        ":folder",
        'if "%~2"=="" goto end',
        "for /L %%N in (1,1,{}) do (".format(SELF_DELETE_ATTEMPTS),
        '  if not exist "%~2" goto end',
        '  rmdir "%~2" >nul 2>&1',
        "  ping -n 2 127.0.0.1 >nul",
        ")",
        ":end",
        'del /F /Q "%~f0" >nul 2>&1',
    ]) + "\r\n"


def _self_delete_command(helper: Path, locked: Path, install_dir: Path,
                         remove_directory: bool) -> str:
    quoted = " ".join('"{}"'.format(p) for p in (
        helper, locked, install_dir if remove_directory else ""))
    return 'cmd.exe /s /c "{}"'.format(quoted)


def schedule_self_delete(locked: Optional[Path], install_dir: Path,
                         remove_directory: bool) -> None:
    if locked is None:
        return

    helper = Path(tempfile.gettempdir()) / "cerf-uninstall.cmd"
    try:
        helper.write_text(_self_delete_script(), encoding="ascii")
        subprocess.Popen(_self_delete_command(helper, locked, install_dir,
                                              remove_directory),
                         cwd=str(helper.parent),
                         creationflags=getattr(subprocess, "DETACHED_PROCESS", 0)
                         | getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError:
        pass
