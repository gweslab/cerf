#include "../../cerf/i18n/translation_catalog.h"

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using cerf::i18n::RenderMessage;
using cerf::i18n::MessageParameters;
using cerf::i18n::TranslationCatalog;

namespace {

void Check(bool condition) {
    if (!condition) throw std::runtime_error("Catalog test failed");
}

template <class Function>
void MustThrow(Function function) {
    bool caught = false;
    try { function(); } catch (const std::exception&) { caught = true; }
    Check(caught);
}

void Write(const std::filesystem::path& path, const std::string& content) {
    std::ofstream stream(path, std::ios::binary);
    stream << content;
    if (!stream.good()) throw std::runtime_error("Cannot write test fixture");
}

}

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
#else
int main(int argc, char** argv) {
#endif
    try {
        if (argc != 3) throw std::runtime_error("Expected scratch and catalog directories");
        const auto directory = std::filesystem::path(argv[1]) /
                               std::filesystem::path(u8"한국어-日本語");
        std::filesystem::create_directories(directory);
        Write(directory / "en.yml",
              "name: English\nmessages:\n"
              "  welcome: \"Hello {name}, {count} files\"\n"
              "  fallback: English fallback\n"
              "  literal: \"{{braces}} and {name}\"\n");
        Write(directory / "ko.yml",
              "name: 한국어\nmessages:\n"
              "  welcome: \"{count}개 파일: {name}님\"\n");
        TranslationCatalog catalog;
        Check(catalog.Load(directory, "ko").empty());
        Check(catalog.Format("welcome", {{"count", "250"}, {"name", "日本語"}}) ==
              "250개 파일: 日本語님");
        Check(catalog.Text("fallback") == "English fallback");
        Check(catalog.Format("literal", {{"name", "{injected}"}}) ==
              "{braces} and {injected}");
        Write(directory / "ko.yml", "name: 한국어\nmessages: {fallback: 변경된 번역}\n");
        Check(catalog.Load(directory, "ko").empty());
        Check(catalog.Text("fallback") == "변경된 번역");
        Write(directory / "ko.yml", "name: 한국어\nmessages: {welcome: \"{wrong}\", fallback: 정상 번역}\n");
        Check(!catalog.Load(directory, "ko").empty());
        Check(catalog.Format("welcome", {{"count", "2"}, {"name", "Ada"}}) ==
              "Hello Ada, 2 files");
        Check(catalog.Text("fallback") == "정상 번역");
        Check(!catalog.Load(directory, "fr").empty());
        Check(catalog.Language() == "en");
        for (const std::string invalid : {"../ko", "ko/ko", "en.yml", "", "EN", "ko\\ko"})
            MustThrow([&] { catalog.Load(directory, invalid); });
        for (const std::string invalid : {
                 "name: English\nname: Other\nmessages: {}",
                 "name: English\nmessages: {test: a, test: b}",
                 "name: English\nmessages: {test: [a]}",
                 "name: English\nmessages: {test: !!python/object:foo bar}",
                 "name: English\nmessages: {}\n---\nname: Other\nmessages: {}",
                 "name: English\nmessages: {test: \"\\0\"}",
                 "!custom {name: English, messages: {}}",
                 "name: English\nmessages: {}",
                 "name: English\nmessages: {test: null}"}) {
            Write(directory / "en.yml", invalid);
            MustThrow([&] { catalog.Load(directory, "en"); });
        }
        Check(catalog.Language() == "en");
        Check(catalog.Text("fallback") == "English fallback");
        for (const std::string invalid : {"{", "}", "{Name}", "{}", "{a.b}", "{x:02d}"})
            MustThrow([&] { MessageParameters(invalid); });
        MustThrow([&] { RenderMessage("{name}", {}); });
        MustThrow([&] { RenderMessage("{name}", {{"name", "Ada"}, {"extra", "1"}}); });
        MustThrow([&] { RenderMessage("{name}", {{"name", "Ada"}, {"name", "Bob"}}); });
        Check(RenderMessage("{name}/{name}", {{"name", "Ada"}}) == "Ada/Ada");
        Check(RenderMessage("{{}}", {}) == "{}");
        for (const std::string language : {"en", "ko", "fr", "ru", "ja", "pl"}) {
            Check(catalog.Load(std::filesystem::path(argv[2]), language).empty());
            Check(catalog.Language() == language);
            Check(!catalog.Text("common.settings").empty());
        }
        std::cout << "Native i18n tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
