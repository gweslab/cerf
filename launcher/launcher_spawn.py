from __future__ import annotations

from typing import List, Optional

from about_window import AboutWindow
from app_paths import FRONTEND_NAME, install_root
from child_process import spawn_detached
from device_state import DeviceBundle
from running_state import show_running_window
from ui_dialogs import show_error


class SpawnMixin:
    def _launch(self, boot: Optional[str] = None) -> None:
        sel = self.tree_panel.selection()
        d = sel.device
        if d is None or self.busy:
            return
        if self.cerf_exe is None:
            show_error(self, "Cannot launch",
                       f"{FRONTEND_NAME} not found in {install_root()}.")
            return
        if not d.is_installed:
            return
        status = self._running_status_for(d)
        if status is not None:
            if not show_running_window(status):
                show_error(self, "Show CERF",
                           f"{d.name} is running but its window could not be focused.")
            return
        self._spawn_cerf(d, boot)

    def _open_about(self) -> None:
        AboutWindow(self).wait()

    def _spawn_cerf(self, d: DeviceBundle, boot: Optional[str] = None) -> None:
        tail = [f"--device={d.name}"]
        if d.name in self._verbose_devices:
            tail.append("--log=ALL")
        tail.append(f"--boot={boot or 'resume'}")
        argv: List[str] = [str(self.cerf_exe)] + tail
        try:
            spawn_detached(argv, self.cerf_exe.parent)
            self.status_bar.set_status(f"Launched {FRONTEND_NAME} for {d.name}.")
        except OSError as exc:
            show_error(self, "Launch failed", str(exc))
