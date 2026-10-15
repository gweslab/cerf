from __future__ import annotations
from i18n import t

from concurrent.futures import Future
from typing import Callable, List, Optional, Tuple

from device_state import DeviceBundle, PackageStatus
from bundle_download import CancelledError
from ui_dialogs import (ask_yesno, confirm_rom_license, show_error,
                        show_info)
from ui_large_download import (filter_update_all_targets, gate_bundle_download,
                               gate_package_download)


class OperationsMixin:
    def _download_selected(self) -> None:
        sel = self.tree_panel.selection()
        if self.busy or self.catalog_loading or sel.device is None:
            return
        if sel.kind == "package" and sel.package is not None:
            self._download_package(sel.device, sel.package)
            return
        d = sel.device
        if d.remote is None:
            return
        if not gate_bundle_download(self, d):
            return
        self._set_busy(True, t('launcher.launcher_operations.downloading_name', name=d.name))
        f = self.manager.submit_install(d, progress=self._progress_cb,
                                        cancel_event=self.cancel_event)
        self._await_future(f, lambda exc: self._after_op(exc, t('launcher.launcher_operations.downloaded_name', name=d.name)))

    def _download_package(self, d: DeviceBundle, ps: PackageStatus) -> None:
        if not d.is_installed:
            show_error(self, t("launcher.launcher_operations.cannot_download_package"),
                       t('launcher.launcher_operations.name_is_not_installed_install_the_device', name=d.name))
            return
        if not gate_package_download(self, d, ps):
            return
        self._set_busy(True, t('launcher.launcher_operations.downloading_name', name=ps.remote.name))
        f = self.manager.submit_install_package(
            d.name, ps.remote.category, ps.remote.key,
            progress=self._progress_cb, cancel_event=self.cancel_event)
        self._await_future(f, lambda exc: self._after_op(
            exc, t('launcher.launcher_operations.installed_name_for_name2', name=ps.remote.name, name2=d.name)))

    def _update_selected(self) -> None:
        sel = self.tree_panel.selection()
        if sel.kind == "device" and sel.device is not None:
            self._apply_device_update(sel.device)

    def _apply_device_update(self, d: DeviceBundle) -> None:
        if self.busy or self.catalog_loading:
            return
        if self._running_status_for(d) is not None:
            show_error(self, t("launcher.launcher_operations.device_is_running"),
                       t('launcher.launcher_operations.value_was_not_updated_because_its_rom', value=d.meta.device_name or d.name))
            return
        if d.has_update:
            self._download_selected()
        elif d.has_cerf_json_update:
            self._refresh_cerf_json(d)

    def _refresh_cerf_json(self, d: DeviceBundle) -> None:
        if self.busy or self.catalog_loading or d.remote is None:
            return
        self._set_busy(True, t('launcher.launcher_operations.updating_name_config', name=d.name))
        f = self.manager.submit_refresh_cerf_json(d.name)
        self._await_future(f, lambda exc: self._after_op(
            exc, t('launcher.launcher_operations.updated_name_config', name=d.name)))

    def _delete_package(self, d: DeviceBundle, ps: PackageStatus) -> None:
        if self.busy:
            return
        if not ask_yesno(self, t("launcher.launcher_operations.delete_package"),
                         t('launcher.launcher_operations.remove_name_devices_name2_key_this_cannot', name=ps.remote.name, name2=d.name, key=ps.remote.key)):
            return
        self._set_busy(True, t('launcher.launcher_operations.deleting_name', name=ps.remote.name))
        f = self.manager.submit_delete_package(d.name, ps.remote.category,
                                               ps.remote.key)
        self._await_future(f, lambda exc: self._after_op(
            exc, t('launcher.launcher_operations.deleted_name', name=ps.remote.name)))

    def _delete_selected(self) -> None:
        sel = self.tree_panel.selection()
        if self.busy or sel.device is None:
            return
        d = sel.device
        if self._running_status_for(d) is not None:
            return
        if sel.kind == "package" and sel.package is not None:
            ps = sel.package
            if not ask_yesno(self, t("launcher.launcher_operations.delete_package"),
                             t('launcher.launcher_operations.remove_name_devices_name2_key_this_cannot', name=ps.remote.name, name2=d.name, key=ps.remote.key)):
                return
            self._set_busy(True, t('launcher.launcher_operations.deleting_name', name=ps.remote.name))
            f = self.manager.submit_delete_package(d.name, ps.remote.category,
                                                   ps.remote.key)
            self._await_future(f, lambda exc: self._after_op(
                exc, t('launcher.launcher_operations.deleted_name', name=ps.remote.name)))
            return
        if not ask_yesno(self, t("launcher.launcher_operations.delete_device"),
                         t('launcher.launcher_operations.remove_devices_name_and_its_files_this', name=d.name)):
            return
        self._set_busy(True, t('launcher.launcher_operations.deleting_name', name=d.name))
        f = self.manager.submit_delete(d.name)
        self._await_future(f, lambda exc: self._after_op(exc, t('launcher.launcher_operations.deleted_name', name=d.name)))

    def _update_all(self) -> None:
        if self.busy or self.catalog_loading:
            return
        devices = self.tree_panel.devices
        running = {d.name for d in devices
                   if self._running_status_for(d) is not None}
        skipped = [d for d in devices if d.name in running
                   and (d.has_update or d.has_cerf_json_update
                        or d.has_package_updates)]
        rom_targets = [d for d in devices
                       if d.has_update and d.name not in running]
        cfg_targets = [d for d in devices
                       if d.has_cerf_json_update and d.name not in running]
        pkg_targets: List[Tuple[DeviceBundle, PackageStatus]] = [
            (d, ps) for d in devices for ps in d.packages
            if ps.has_update and d.name not in running]
        if skipped:
            show_error(self, t("launcher.launcher_operations.devices_are_running"),
                       "These devices were not updated because their ROM is "
                       "running:\n" + "\n".join(
                           f"• {d.meta.device_name or d.name}" for d in skipped))
        if not rom_targets and not cfg_targets and not pkg_targets:
            if not skipped:
                show_info(self, t("launcher.launcher_operations.update_all"),
                          "All installed bundles and packages are up to date.")
            return
        filtered = filter_update_all_targets(self, rom_targets, pkg_targets)
        if filtered is None:
            return
        rom_targets, pkg_targets = filtered
        total = len(rom_targets) + len(pkg_targets) + len(cfg_targets)
        if not total:
            show_info(self, t("launcher.launcher_operations.update_all"),
                      "Only large bundles need updating - update each from the "
                      "table individually.")
            return
        if (rom_targets or pkg_targets) and not confirm_rom_license(
                self, f"{total} item(s)", self.manager.repo_abuse_contacts):
            return
        self._set_busy(True, t('launcher.launcher_operations.updating_total_item_s', total=total))
        work: List[Tuple[str, Callable[[], Future]]] = []
        for d in rom_targets:
            work.append((d.name, lambda dev=d: self.manager.submit_install(
                dev, progress=self._progress_cb, cancel_event=self.cancel_event)))
        for d, ps in pkg_targets:
            work.append((f"{d.name}: {ps.remote.name}",
                         lambda name=d.name, c=ps.remote.category, k=ps.remote.key:
                         self.manager.submit_install_package(
                             name, c, k, progress=self._progress_cb,
                             cancel_event=self.cancel_event)))
        for d in cfg_targets:
            work.append((f"{d.name} config",
                         lambda name=d.name:
                         self.manager.submit_refresh_cerf_json(name)))
        self._run_sequence(work)

    def _run_sequence(self, work: List[Tuple[str, Callable[[], Future]]]) -> None:
        errors: List[tuple[str, BaseException]] = []
        def step(idx: int) -> None:
            if idx >= len(work):
                self._set_busy(False)
                if errors:
                    summary = "\n".join(f"{n}: {e}" for n, e in errors)
                    show_error(self, t("launcher.launcher_operations.sequence_completed_with_errors"), summary)
                self._reload_device_list()
                return
            label, submit = work[idx]
            self.status_bar.set_status(f"[{idx+1}/{len(work)}] {label}…")
            def finished(exc: Optional[BaseException]) -> None:
                if exc is not None and not isinstance(exc, CancelledError):
                    errors.append((label, exc))
                else:
                    self._reload_device_list()
                step(idx + 1)
            self._await_future(submit(), finished)
        step(0)

    def _after_op(self, exc: Optional[BaseException], success_msg: str) -> None:
        self._set_busy(False)
        if exc is not None:
            if isinstance(exc, CancelledError):
                self.status_bar.set_status(t("launcher.launcher_operations.cancelled"))
            else:
                show_error(self, t("launcher.launcher_operations.operation_failed"), str(exc))
                self.status_bar.set_status(t("launcher.launcher_operations.error"))
        else:
            self.status_bar.set_status(success_msg)
        self._reload_device_list()
