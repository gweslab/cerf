from __future__ import annotations

from pathlib import Path
from typing import Callable

import install_registry
import install_shortcuts
from app_paths import resolve_version, resolve_version_tuple
from install_options import InstallOptions
from retry_gate import RetryFn, attempt

LogFn = Callable[[str], None]


def _plain_version() -> str:
    numbers = resolve_version_tuple()
    if numbers is None:
        return resolve_version()
    return ".".join(str(n) for n in numbers)


def _create(what: str, action: Callable[[], object], log: LogFn,
            ask_retry: RetryFn) -> None:
    log("Creating " + what)
    error = attempt("Create failed", "Creating " + what, action, ask_retry)
    if error is not None:
        log("  {} not created ({})".format(what, error))


def finalize(install_dir: Path, options: InstallOptions, log: LogFn,
             ask_retry: RetryFn) -> None:
    if options.desktop_icon:
        _create("the desktop shortcut",
                lambda: install_shortcuts.create_desktop_shortcut(install_dir),
                log, ask_retry)
    if options.start_menu:
        _create("the Start menu entries",
                lambda: install_shortcuts.create_start_menu_entries(
                    install_dir), log, ask_retry)
    if not options.fresh:
        return
    _create("the Programs and Features entry",
            lambda: install_registry.register(install_dir, _plain_version()),
            log, ask_retry)
