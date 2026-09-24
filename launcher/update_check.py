from __future__ import annotations

import os
import threading
import webbrowser
from pathlib import Path
from typing import Optional

from app_paths import exe_dir, resolve_version_tuple
from app_settings import CHANNEL_DISABLED, read_update_channel
from bundles import parse_version_tuple
from available_update import AvailableUpdate
import upgrade_dialog
from ui_dialogs import show_dialog, show_error
from upgrade_download import download_upgrade
from upgrade_process import (INSTALL_FLAG, UPGRADE_DIR_NAME, UpgradeError,
                             launcher_exe_in, spawn_stage, stage_argument,
                             wait_for_cerf_exit)
from upgrade_window import UpgradeWindow
import ui_theme as theme


class UpdateCheck:
    def __init__(self, app) -> None:
        self.app = app
        self.release: Optional[AvailableUpdate] = None

    def start(self) -> None:
        self.release = None
        if read_update_channel() == CHANNEL_DISABLED:
            self._no_update()
            return
        self.app.status_bar.set_update_status("Checking updates…", theme.FG_DIM,
                                              link=False)
        future = self.app.manager.submit_release_check()

        def done(exc: Optional[BaseException]) -> None:
            if exc is not None:
                self._no_update()
                return
            release = future.result()
            if release is None:
                self._no_update()
                return
            self._apply_release(release)

        self.app._await_future(future, done)

    def _is_newer(self, tag: str) -> bool:
        current = resolve_version_tuple()
        remote = parse_version_tuple(tag)
        return current is not None and remote is not None and remote > current

    def _announce(self, version: str) -> None:
        self.app.status_bar.set_update_status(
            f"CERF {version} is available", theme.UPDATE_LINK, link=True,
            on_click=self.open_offer)

    def _no_update(self) -> None:
        self.app.status_bar.set_update_status("", theme.FG_DIM, link=False)

    def _apply_release(self, release: AvailableUpdate) -> None:
        if not self._is_newer(release.tag):
            self._no_update()
            return
        self.release = release
        self._announce(release.tag)
        self.open_offer()

    def open_offer(self) -> None:
        choice = upgrade_dialog.show_release_available(self.app, self.release)
        if choice == upgrade_dialog.UPGRADE:
            self._start_upgrade()
        elif choice == upgrade_dialog.BROWSER:
            webbrowser.open(self.release.html_url)

    def _cerf_is_clear(self) -> bool:
        def ask_retry(title: str, message: str) -> bool:
            return show_dialog(self.app, title, message, ("Retry", "Cancel"),
                               default="Cancel") == "Retry"

        try:
            return wait_for_cerf_exit(ask_retry, exe_dir())
        except UpgradeError as exc:
            show_error(self.app, "Upgrade", str(exc))
            return False

    def _start_upgrade(self) -> None:
        if self.release is None or not self._cerf_is_clear():
            return
        install_dir = exe_dir()
        window = UpgradeWindow(
            self.app,
            f"Upgrading CE Runtime Foundation to {self.release.tag}…",
            lambda exc: self._download_finished(exc, window, install_dir))
        threading.Thread(target=self._download, args=(window, install_dir),
                         daemon=True).start()

    def _download(self, window: UpgradeWindow, install_dir: Path) -> None:
        try:
            download_upgrade(self.release, install_dir, window.post_log,
                             window.post_progress)
        except BaseException as exc:
            window.post_result(exc)
            return
        window.post_result(None)

    def _download_finished(self, error: Optional[BaseException],
                           window: UpgradeWindow, install_dir: Path) -> None:
        if error is None:
            staged = install_dir / UPGRADE_DIR_NAME
            try:
                spawn_stage(launcher_exe_in(staged),
                            stage_argument(os.getpid(), INSTALL_FLAG), staged)
            except UpgradeError as exc:
                error = exc
        if error is not None:
            window.destroy()
            show_error(self.app, "Upgrade failed",
                       f"{error}\n\nYour installation is untouched.")
            return
        self.app._on_close()
