from __future__ import annotations

import tkinter as tk

from app_paths import resolve_version
from i18n import t
from settings_dialog import SettingsDialog


class LanguageMixin:
    def _open_settings(self) -> None:
        SettingsDialog(self, on_update_channel_changed=self.update_check.start,
                       on_language_changed=self._apply_language)

    def _apply_language(self) -> None:
        selection = self.tree_panel.selection().device
        selected_name = selection.name if selection else None
        query = self.status_bar.search.query()
        sash = self.paned.sash_coord(0)
        for widget in self.winfo_children():
            if not isinstance(widget, tk.Toplevel):
                widget.destroy()
        self.title(t("launcher.title", version=resolve_version()))
        self._build_ui()
        self._reload_device_list()
        if selected_name:
            self.tree_panel.select_device(selected_name)
        self.status_bar.search.set_query(query)
        self.update_idletasks()
        self.paned.sash_place(0, *sash)
        self.toolbar.set_busy(self.busy)
        self._refresh_selection_state()
        self.update_check.refresh_text()
        self._surface_repo_errors()
