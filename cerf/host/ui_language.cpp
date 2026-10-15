#include "ui_language.h"

#include "../core/cerf_emulator.h"
#include "../core/cerf_paths.h"
#include "../core/log.h"
#include "../core/string_utils.h"

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>

REGISTER_SERVICE(UiLanguage);

void UiLanguage::OnReady() {
    std::string language = "en";
    if (emu_.Config().language) {
        language = emu_.Config().language;
    } else {
        std::ifstream config(Utf8ToWide((GetCerfDir() + "cerf.json").c_str()));
        if (config) {
            try {
                const auto root = nlohmann::json::parse(config);
                language = root.value("language", std::string("en"));
            } catch (const std::exception& error) {
                LOG(Caution, "[I18N] config: %s\n", error.what());
            }
        }
    }
    if (!cerf::i18n::IsLanguageCode(language)) {
        LOG(Caution, "[I18N] invalid language: %s\n", language.c_str());
        language = "en";
    }
    try {
        const auto directory = std::filesystem::path(Utf8ToWide(GetCerfDir().c_str())) / L"langs";
        for (const auto& warning : catalog_.Load(directory, language))
            LOG(Caution, "[I18N] %s\n", warning.c_str());
        for (const auto& [key, value] : catalog_.Messages()) {
            if (!cerf::i18n::MessageParameters(value).empty()) continue;
            const auto rendered = cerf::i18n::RenderMessage(value, {});
            wide_messages_.emplace(key, Utf8ToWide(rendered.c_str()));
        }
    } catch (const std::exception& error) {
        LOG(Caution, "[I18N] English catalog unavailable: %s\n", error.what());
        CerfFatalExit(CERF_FATAL_USER_ERROR);
    }
}

const wchar_t* UiLanguage::Text(std::string_view key) const {
    const auto found = wide_messages_.find(key);
    if (found == wide_messages_.end()) throw std::out_of_range("Unknown message: " + std::string(key));
    return found->second.c_str();
}

std::wstring UiLanguage::Format(std::string_view key,
                               std::initializer_list<cerf::i18n::MessageArgument> arguments) const {
    return Utf8ToWide(catalog_.Format(key, arguments).c_str());
}
