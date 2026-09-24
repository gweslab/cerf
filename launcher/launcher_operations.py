from __future__ import annotations

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
        self._set_busy(True, f"Downloading {d.name}…")
        f = self.manager.submit_install(d, progress=self._progress_cb,
                                        cancel_event=self.cancel_event)
        self._await_future(f, lambda exc: self._after_op(exc, f"Downloaded {d.name}"))

    def _download_package(self, d: DeviceBundle, ps: PackageStatus) -> None:
        if not d.is_installed:
            show_error(self, "Cannot download package",
                       f"{d.name} is not installed; install the device first.")
            return
        if not gate_package_download(self, d, ps):
            return
        self._set_busy(True, f"Downloading {ps.remote.name}…")
        f = self.manager.submit_install_package(
            d.name, ps.remote.category, ps.remote.key,
            progress=self._progress_cb, cancel_event=self.cancel_event)
        self._await_future(f, lambda exc: self._after_op(
            exc, f"Installed {ps.remote.name} for {d.name}"))

    def _update_selected(self) -> None:
        sel = self.tree_panel.selection()
        if sel.kind == "device" and sel.device is not None:
            self._apply_device_update(sel.device)

    def _apply_device_update(self, d: DeviceBundle) -> None:
        if self.busy or self.catalog_loading:
            return
        if self._running_status_for(d) is not None:
            show_error(self, "Device is running",
                       f"{d.meta.device_name or d.name} was not updated because "
                       f"its ROM is running. Close it and try again.")
            return
        if d.has_update:
            self._download_selected()
        elif d.has_cerf_json_update:
            self._refresh_cerf_json(d)

    def _refresh_cerf_json(self, d: DeviceBundle) -> None:
        if self.busy or self.catalog_loading or d.remote is None:
            return
        self._set_busy(True, f"Updating {d.name} config…")
        f = self.manager.submit_refresh_cerf_json(d.name)
        self._await_future(f, lambda exc: self._after_op(
            exc, f"Updated {d.name} config"))

    def _delete_package(self, d: DeviceBundle, ps: PackageStatus) -> None:
        if self.busy:
            return
        if not ask_yesno(self, "Delete package",
                         f"Remove {ps.remote.name} "
                         f"(devices/{d.name}/{ps.remote.key})?\n"
                         f"This cannot be undone."):
            return
        self._set_busy(True, f"Deleting {ps.remote.name}…")
        f = self.manager.submit_delete_package(d.name, ps.remote.category,
                                               ps.remote.key)
        self._await_future(f, lambda exc: self._after_op(
            exc, f"Deleted {ps.remote.name}"))

    def _delete_selected(self) -> None:
        sel = self.tree_panel.selection()
        if self.busy or sel.device is None:
            return
        d = sel.device
        if self._running_status_for(d) is not None:
            return
        if sel.kind == "package" and sel.package is not None:
            ps = sel.package
            if not ask_yesno(self, "Delete package",
                             f"Remove {ps.remote.name} "
                             f"(devices/{d.name}/{ps.remote.key})?\n"
                             f"This cannot be undone."):
                return
            self._set_busy(True, f"Deleting {ps.remote.name}…")
            f = self.manager.submit_delete_package(d.name, ps.remote.category,
                                                   ps.remote.key)
            self._await_future(f, lambda exc: self._after_op(
                exc, f"Deleted {ps.remote.name}"))
            return
        if not ask_yesno(self, "Delete device",
                         f"Remove devices/{d.name}/ and its files?\nThis cannot be undone."):
            return
        self._set_busy(True, f"Deleting {d.name}…")
        f = self.manager.submit_delete(d.name)
        self._await_future(f, lambda exc: self._after_op(exc, f"Deleted {d.name}"))

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
            show_error(self, "Devices are running",
                       "These devices were not updated because their ROM is "
                       "running:\n" + "\n".join(
                           f"• {d.meta.device_name or d.name}" for d in skipped))
        if not rom_targets and not cfg_targets and not pkg_targets:
            if not skipped:
                show_info(self, "Update all",
                          "All installed bundles and packages are up to date.")
            return
        filtered = filter_update_all_targets(self, rom_targets, pkg_targets)
        if filtered is None:
            return
        rom_targets, pkg_targets = filtered
        total = len(rom_targets) + len(pkg_targets) + len(cfg_targets)
        if not total:
            show_info(self, "Update all",
                      "Only large bundles need updating - update each from the "
                      "table individually.")
            return
        if (rom_targets or pkg_targets) and not confirm_rom_license(
                self, f"{total} item(s)", self.manager.repo_abuse_contacts):
            return
        self._set_busy(True, f"Updating {total} item(s)…")
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
                    show_error(self, "Sequence completed with errors", summary)
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
                self.status_bar.set_status("Cancelled.")
            else:
                show_error(self, "Operation failed", str(exc))
                self.status_bar.set_status("Error.")
        else:
            self.status_bar.set_status(success_msg)
        self._reload_device_list()
