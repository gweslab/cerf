import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "launcher"))

from yaml_catalog import (TranslationCatalog, format_message,
                          message_parameters, read_catalog)


class CatalogTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="CERF-한국어-日本語-")
        self.directory = Path(self.temporary.name)
        (self.directory / "en.yml").write_text(
            'name: "English"\nmessages:\n'
            '  welcome: "Hello {name}, {count} files"\n'
            '  fallback: "English fallback"\n'
            '  literal: "{{braces}} and {name}"\n', encoding="utf-8")
        (self.directory / "ko.yml").write_text(
            'name: "한국어"\nmessages:\n'
            '  welcome: "{count}개 파일: {name}님"\n', encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def test_utf8_reordering_and_fallback(self):
        catalog = TranslationCatalog()
        self.assertEqual(catalog.load(self.directory, "ko"), [])
        self.assertEqual(catalog.text("welcome", name="日本語", count=250), "250개 파일: 日本語님")
        self.assertEqual(catalog.text("fallback"), "English fallback")
        self.assertEqual(catalog.text("literal", name="{injected}"), "{braces} and {injected}")

    def test_placeholder_error_uses_english_for_that_message(self):
        (self.directory / "ko.yml").write_text(
            'name: "한국어"\nmessages:\n  welcome: "{wrong}"\n'
            '  fallback: "정상 번역"\n', encoding="utf-8")
        catalog = TranslationCatalog()
        self.assertTrue(catalog.load(self.directory, "ko"))
        self.assertEqual(catalog.text("welcome", name="Ada", count=2), "Hello Ada, 2 files")
        self.assertEqual(catalog.text("fallback"), "정상 번역")

    def test_missing_and_invalid_language_pack(self):
        catalog = TranslationCatalog()
        self.assertTrue(catalog.load(self.directory, "fr"))
        self.assertEqual(catalog.language, "en")
        (self.directory / "ko.yml").write_text("[invalid", encoding="utf-8")
        self.assertTrue(catalog.load(self.directory, "ko"))
        self.assertEqual(catalog.text("fallback"), "English fallback")

    def test_language_codes_cannot_escape_directory(self):
        catalog = TranslationCatalog()
        for language in ("../ko", "ko/ko", "en.yml", "", "EN", "ko\\ko"):
            with self.assertRaises(ValueError):
                catalog.load(self.directory, language)

    def test_duplicates_tags_nested_values_and_documents(self):
        invalid = (
            'name: English\nname: Other\nmessages: {}',
            'name: English\nmessages: {test: a, test: b}',
            'name: English\nmessages: {test: [a]}',
            'name: English\nmessages: {test: !!python/object:foo bar}',
            'name: English\nmessages: {}\n---\nname: Other\nmessages: {}',
            'name: English\nmessages: {test: "\\0"}',
            '!custom {name: English, messages: {}}',
            'name: English\nmessages: {test: null}',
        )
        for content in invalid:
            path = self.directory / "invalid.yml"
            path.write_text(content, encoding="utf-8")
            with self.assertRaises(Exception):
                read_catalog(path)

    def test_failed_reload_is_atomic(self):
        catalog = TranslationCatalog()
        catalog.load(self.directory, "ko")
        (self.directory / "en.yml").write_text("[invalid", encoding="utf-8")
        with self.assertRaises(Exception):
            catalog.load(self.directory, "en")
        self.assertEqual(catalog.language, "ko")
        self.assertEqual(catalog.text("welcome", name="Ada", count=3), "3개 파일: Ada님")

    def test_reloads_edited_external_catalog(self):
        catalog = TranslationCatalog()
        catalog.load(self.directory, "ko")
        (self.directory / "ko.yml").write_text(
            'name: 한국어\nmessages: {fallback: 변경된 번역}\n', encoding="utf-8")
        self.assertEqual(catalog.load(self.directory, "ko"), [])
        self.assertEqual(catalog.text("fallback"), "변경된 번역")
        (self.directory / "en.yml").write_text(
            'name: English\nmessages: {}\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            catalog.load(self.directory, "en")

    def test_invalid_calls_and_braces(self):
        for message in ("{", "}", "{Name}", "{}", "{a.b}", "{x:02d}"):
            with self.assertRaises(ValueError):
                message_parameters(message)
        with self.assertRaises(ValueError):
            format_message("{name}")
        with self.assertRaises(ValueError):
            format_message("{name}", name="Ada", extra=1)
        self.assertEqual(format_message("{name}/{name}", name="Ada"), "Ada/Ada")
        self.assertEqual(format_message("{{}}"), "{}")

    def test_metadata_id_does_not_overwrite_custom_or_updated_text(self):
        catalog = TranslationCatalog()
        catalog.load(self.directory, "ko")
        self.assertEqual(catalog.data_text("fallback", "English fallback"), "English fallback")
        self.assertEqual(catalog.data_text("welcome", "My edited description"), "My edited description")
        self.assertEqual(catalog.data_text("missing", "New metadata"), "New metadata")
        (self.directory / "ko.yml").write_text(
            'name: 한국어\nmessages: {fallback: 번역된 설명}\n', encoding="utf-8")
        catalog.load(self.directory, "ko")
        self.assertEqual(catalog.data_text("fallback", "English fallback"), "번역된 설명")
        self.assertEqual(catalog.data_text("fallback", "Updated English description"),
                         "Updated English description")

    def test_complete_bundled_languages_have_all_default_keys(self):
        english = read_catalog(ROOT / "langs" / "en.yml")[1]
        for language in ("ko", "fr", "ja", "ru", "pl"):
            messages = read_catalog(ROOT / "langs" / (language + ".yml"))[1]
            self.assertEqual(set(messages), set(english), language)
            for key, original in english.items():
                self.assertEqual(message_parameters(messages[key]),
                                 message_parameters(original), (language, key))


if __name__ == "__main__":
    unittest.main()
