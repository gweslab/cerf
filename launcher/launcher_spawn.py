from __future__ import annotations
from i18n import t

import subprocess
from typing import List, Optional

from about_window import AboutWindow
from i18n import current_language
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
            show_error(self, t("launcher.launcher_spawn.cannot_launch"), "cerf.exe not found next to launcher.exe.")
            return
        if not d.is_installed:
            return
        status = self._running_status_for(d)
        if status is not None:
            if not show_running_window(status):
                show_error(self, t("launcher.launcher_app.show_cerf"),
                           t('launcher.launcher_spawn.name_is_running_but_its_window_could', name=d.name))
            return
        self._spawn_cerf(d, boot)

    def _open_about(self) -> None:
        AboutWindow(self).wait()

    def _spawn_cerf(self, d: DeviceBundle, boot: Optional[str] = None) -> None:
        tail = [f"--device={d.name}"]
        if d.name in self._verbose_devices:
            tail.append("--log=ALL")
        tail.append(f"--boot={boot or 'resume'}")
        tail.append("--language=" + current_language())
        argv: List[str] = [str(self.cerf_exe)] + tail
        try:
            subprocess.Popen(argv, cwd=str(self.cerf_exe.parent),
                             creationflags=getattr(subprocess, "DETACHED_PROCESS", 0))
            self.status_bar.set_status(t('launcher.launcher_spawn.launched_cerf_exe_for_name', name=d.name))
        except OSError as exc:
            show_error(self, t("launcher.launcher_spawn.launch_failed"), str(exc))
