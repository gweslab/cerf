from __future__ import annotations

import tkinter as tk
from typing import Optional, Set

from device_state import DeviceBundle
from properties_dialog import MODE_EDIT, MODE_LOCKED, PropertiesDialog
from properties_model import PropertiesModel, PropertiesSubject
from properties_page_board import PAGE_BOARD
from ui_dialogs import show_error


class PropertiesMixin:
    _verbose_devices: Set[str]

    def _properties_model(self, d: DeviceBundle) -> PropertiesModel:
        subject = PropertiesSubject.of_bundle(self.manager.devices_dir, d)
        return PropertiesModel(subject, d.name in self._verbose_devices)

    def _show_config(self, d: Optional[DeviceBundle]) -> None:
        if d is None or not d.is_installed:
            self.config_preview.clear()
            return
        self.config_preview.show(self._properties_model(d))

    def _open_properties(self, page: str = PAGE_BOARD) -> None:
        d = self.tree_panel.selection().device
        if self.busy or d is None or not d.is_installed:
            return
        model = self._properties_model(d)
        running = self._running_status_for(d) is not None

        def accept(dlg: tk.Misc) -> bool:
            try:
                model.save_all()
            except OSError as exc:
                show_error(dlg, "Properties", "Could not save:\n{}".format(exc))
                return False
            if model.values["verbose_logs"]:
                self._verbose_devices.add(d.name)
            else:
                self._verbose_devices.discard(d.name)
            self._saved_state_warning.maybe_warn(model.subject.device_dir)
            return True

        dialog = PropertiesDialog(self, model,
                                  MODE_LOCKED if running else MODE_EDIT,
                                  page, accept)
        if dialog.run():
            self._reload_device_list()
            self.tree_panel.select_device(d.name)
