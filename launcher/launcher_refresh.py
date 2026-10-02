from __future__ import annotations

from typing import Callable, List, Optional

from bundles import ManifestVersionError
from device_state import DeviceBundle
from ui_dialogs import show_error, show_info


class RefreshMixin:
    def _refresh_manifest(self) -> None:
        if self.busy or self.catalog_loading:
            return
        self._set_catalog_loading(True, "Fetching bundle catalog…")
        future = self.manager.submit_refresh()

        def done(exc: Optional[BaseException]) -> None:
            self._set_catalog_loading(False)
            if isinstance(exc, ManifestVersionError):
                self._show_manifest_version_error(exc)
            elif exc is not None:
                show_error(self, "Operation failed", str(exc))
            else:
                self._surface_repo_errors()
            self._reload_device_list()
        self._await_future(future, done)

    def _surface_repo_errors(self) -> None:
        count = len(self.manager.repo_errors)
        if count:
            self.status_bar.set_status("{} bundle {} unavailable".format(
                count, "repository" if count == 1 else "repositories"))

    def _reload_download_sources(
            self,
            done: Callable[[List[DeviceBundle], list, Optional[dict]], None]
    ) -> None:
        if self.busy or self.catalog_loading:
            done(self.tree_panel.devices, self.manager.repo_errors,
                 self.manager.download_places)
            return
        self._set_catalog_loading(True, "Fetching bundle catalog…")
        future = self.manager.submit_refresh()

        def cb(exc: Optional[BaseException]) -> None:
            self._set_catalog_loading(False)
            if isinstance(exc, ManifestVersionError):
                self._show_manifest_version_error(exc)
            elif exc is not None:
                show_error(self, "Operation failed", str(exc))
            else:
                if self.manager.all_repositories_failed:
                    show_error(self, "Remote manifest unavailable", "\n\n".join(
                        "Repository {} failed to load\n\n{}".format(url, error)
                        for url, error in self.manager.repo_errors))
                self._surface_repo_errors()
            self._reload_device_list()
            done(self.manager.list_devices(), self.manager.repo_errors,
                 self.manager.download_places)
        self._await_future(future, cb)

    def _show_manifest_version_error(self, exc: ManifestVersionError) -> None:
        if exc.remote_is_newer:
            show_info(self, "A newer CERF build is required",
                      f"The bundle catalog uses a newer format (manifest "
                      f"version {exc.remote_version}) than this build understands "
                      f"({exc.supported_version}).\n\nDownload a newer CERF build:\n"
                      f"https://cerf.cx/download/\n\n"
                      f"Your installed devices remain available to launch.")
        else:
            show_error(self, "Remote manifest outdated",
                       f"The server's catalog (manifest version "
                       f"{exc.remote_version}) is older than this build expects "
                       f"({exc.supported_version}). Usually temporary - try later.")
