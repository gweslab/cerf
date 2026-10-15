import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "launcher"))

from i18n import available_languages, set_language, t
from operations import BundleManager
from app_paths import resolve_version
from launcher_app import LauncherApp
from settings_dialog import SettingsDialog
from properties_page_ga import GuestAdditionsPage
from download_window import DownloadWindow
from board_info import board_extra_notes, support_label
from board_database import board
from board_picker import BoardPicker
from cpu_config import value_label
from database_text import field_text
from device_file_types import device_file_types
from device_state import parse_cerf_json_object
from transactional_about import _device_line
from i18n import data_text


class LauncherLanguageTest(unittest.TestCase):
    def test_language_switch_keeps_process_and_reads_shared_catalog(self):
        with tempfile.TemporaryDirectory() as temporary:
            manager = BundleManager(Path(temporary))
            set_language("en")
            app = LauncherApp(manager, None)
            app.withdraw()
            self.assertEqual(str(app.toolbar.btn_new.cget("text")), "New")
            self.assertEqual(str(app.toolbar.btn_feedback.cget("text")), "Feedback")
            self.assertTrue(app.toolbar.btn_new.cget("image"))
            app.status_bar.search.set_query("한국어 ROM")
            original_window = app.winfo_id()
            for language in ("ko", "fr", "ru", "ja", "pl", "en"):
                set_language(language)
                app._apply_language()
                self.assertEqual(app.winfo_id(), original_window)
                self.assertEqual(str(app.toolbar.btn_new.cget("text")), t("common.new"))
                self.assertEqual(app.status_bar.search.query(), "한국어 ROM")
                self.assertEqual(app.title(), t("launcher.title", version=resolve_version()))
                settings = SettingsDialog(app)
                self.assertEqual(settings._dlg.title(), t("common.settings"))
                self.assertTrue({"en", "ko", "fr", "ru", "ja", "pl"}.issubset(
                    {code for code, _ in settings._languages}))
                self.assertEqual(settings._label_for("stable"), t("settings.updates_stable"))
                settings._channel_combo.current(2)
                self.assertEqual(settings._selected_channel(), "unstable")
                settings._dlg.destroy()
                page = GuestAdditionsPage(app, app, lambda: None)
                self.assertEqual(t(page.title), t("common.guest_additions"))
                page.frame.destroy()
            app._on_close()

    def test_missing_translation_retains_original_text(self):
        set_language("fr")
        self.assertEqual(t("settings.language"), "Langue")
        self.assertEqual(t("task_manager.process_count_partial", count=2, total=40),
                         "Gestionnaire des tâches invité — processus : 2/40")
        self.assertIn(("ko", "한국어"), available_languages())

    def test_existing_dialog_preserves_sort_identity_after_language_change(self):
        import tkinter as tk
        import ui_theme as theme
        set_language("en")
        root = tk.Tk()
        root.withdraw()
        theme.apply_theme(root)
        try:
            dialog = DownloadWindow(root, [], lambda _: None, lambda: [],
                                    download_places={})
            dialog.sort_combo.current(0)
            set_language("ko")
            self.assertEqual(dialog._sort_mode(), "downloads")
            dialog.sort_combo.current(1)
            self.assertEqual(dialog._sort_mode(), "regular")
            dialog._dlg.destroy()
        finally:
            root.destroy()

    def test_discovers_new_language_file_without_code_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "en.yml").write_bytes((ROOT / "langs" / "en.yml").read_bytes())
            (directory / "pt-BR.yml").write_text(
                'name: "Português (Brasil)"\nmessages: {common.new: "Novo"}\n',
                encoding="utf-8")
            with patch("i18n.catalog_directory", return_value=directory):
                self.assertIn(("pt-BR", "Português (Brasil)"), available_languages())
                set_language("pt-BR")
                self.assertEqual(t("common.new"), "Novo")
                self.assertEqual(t("common.settings"), "Settings")
            set_language("en")

    def test_database_labels_leave_configuration_and_custom_metadata_intact(self):
        import cpu_config
        set_language("ko")
        self.assertIn("에뮬레이션 장치", _device_line({"board_name": "Device Emulator"}))
        files = device_file_types("devemu")
        self.assertEqual(files[0].id, "primary")
        self.assertEqual(files[0].name, "일반 NK/XIP/NB0")
        self.assertIn("640×480", board_extra_notes("devemu")[0])
        self.assertIn("기본 비디오 드라이버", board_extra_notes("devemu")[0])
        self.assertEqual(board("devemu")["support_level"], "bootable_full")
        self.assertIn("전체 지원", support_label("bootable_full"))
        param = next(p for p in cpu_config.params_for_arch("ARM") if p["id"] == "pc_store_offset")
        self.assertEqual(field_text("cpu_config_params", param), "저장되는 PC 값")
        self.assertEqual(value_label(param, "plus_8"), "명령어 주소 + 8")
        self.assertEqual(param["enum_values"][0]["id"], "plus_8")
        meta, _, _ = parse_cerf_json_object({"meta": {
            "description": "Sysgened, includes most of the components.",
            "description_key": "metadata.rom.sysgen_components"}})
        self.assertIn("구성 요소", data_text(meta.description_key, meta.description))
        self.assertEqual(data_text(meta.description_key, "User description"), "User description")
        meta, _, _ = parse_cerf_json_object({"meta": {
            "notes": ["", "English note", "New note"],
            "note_keys": ["", "known.note", ""]}})
        self.assertEqual(meta.notes, ["English note", "New note"])
        self.assertEqual(meta.note_keys, ["known.note", ""])

    def test_localized_board_picker_returns_original_board_id(self):
        import tkinter as tk
        import ui_theme as theme
        set_language("ko")
        root = tk.Tk()
        root.withdraw()
        theme.apply_theme(root)
        chosen = []
        try:
            picker = BoardPicker(root, "devemu", chosen.append)
            self.assertEqual(picker.tree.heading("support", "text"), "에뮬레이션 지원 범위")
            self.assertIn("전체 지원", picker.tree.item("devemu", "values")[1])
            picker._confirm()
            self.assertEqual(chosen, ["devemu"])
        finally:
            root.destroy()

    def test_bulk_update_choice_keeps_device_identity_when_language_changes(self):
        from types import SimpleNamespace
        from ui_large_download import filter_update_all_targets
        small = SimpleNamespace(name="small", meta=SimpleNamespace(device_name="Small"),
                                remote=SimpleNamespace(archive_size=1024))
        large = SimpleNamespace(name="large", meta=SimpleNamespace(device_name="Large"),
                                remote=SimpleNamespace(archive_size=400 * 1024 * 1024))
        set_language("pl")

        def skip_large(*args, **kwargs):
            self.assertEqual(kwargs["buttons"][1], "Pomiń duże pliki")
            set_language("ja")
            return kwargs["buttons"][1]

        with patch("ui_large_download.show_dialog", side_effect=skip_large):
            targets, packages = filter_update_all_targets(None, [small, large], [])
        self.assertEqual(targets, [small])
        self.assertEqual(packages, [])


if __name__ == "__main__":
    unittest.main()
