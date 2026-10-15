from __future__ import annotations
from i18n import t

from typing import Callable, List, Optional

from bundles import ManifestVersionError
from device_state import DeviceBundle
from ui_dialogs import show_error, show_info


class RefreshMixin:
    def _refresh_manifest(self) -> None:
        if self.busy or self.catalog_loading:
            return
        self._set_catalog_loading(True, t("launcher.fetching_catalog"))
        future = self.manager.submit_refresh()

        def done(exc: Optional[BaseException]) -> None:
            self._set_catalog_loading(False)
            if isinstance(exc, ManifestVersionError):
                self._show_manifest_version_error(exc)
            elif exc is not None:
                show_error(self, t("launcher.launcher_operations.operation_failed"), str(exc))
            else:
                self._surface_repo_errors()
            self._reload_device_list()
        self._await_future(future, done)

    def _surface_repo_errors(self) -> None:
        count = len(self.manager.repo_errors)
        if count:
            self.status_bar.set_status(t("launcher.unavailable_repositories", count=count))

    def _reload_download_sources(
            self,
            done: Callable[[List[DeviceBundle], list, Optional[dict]], None]
    ) -> None:
        if self.busy or self.catalog_loading:
            done(self.tree_panel.devices, self.manager.repo_errors,
                 self.manager.download_places)
            return
        self._set_catalog_loading(True, t("launcher.fetching_catalog"))
        future = self.manager.submit_refresh()

        def cb(exc: Optional[BaseException]) -> None:
            self._set_catalog_loading(False)
            if isinstance(exc, ManifestVersionError):
                self._show_manifest_version_error(exc)
            elif exc is not None:
                show_error(self, t("launcher.launcher_operations.operation_failed"), str(exc))
            else:
                if self.manager.all_repositories_failed:
                    show_error(self, t("launcher.launcher_refresh.remote_manifest_unavailable"), "\n\n".join(
                        t('launcher.launcher_refresh.repository_url_failed_to_load_error', url=url, error=error)
                        for url, error in self.manager.repo_errors))
                self._surface_repo_errors()
            self._reload_device_list()
            done(self.manager.list_devices(), self.manager.repo_errors,
                 self.manager.download_places)
        self._await_future(future, cb)

    def _show_manifest_version_error(self, exc: ManifestVersionError) -> None:
        if exc.remote_is_newer:
            show_info(self, t("launcher.launcher_refresh.a_newer_cerf_build_is_required"),
                      t('launcher.launcher_refresh.the_bundle_catalog_uses_a_newer_format', remote_version=exc.remote_version, supported_version=exc.supported_version))
        else:
            show_error(self, t("launcher.launcher_refresh.remote_manifest_outdated"),
                       t('launcher.launcher_refresh.the_server_s_catalog_manifest_version_remote', remote_version=exc.remote_version, supported_version=exc.supported_version))
