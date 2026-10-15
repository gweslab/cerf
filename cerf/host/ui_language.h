#pragma once

#include "../core/service.h"
#include "../i18n/translation_catalog.h"

#include <map>
#include <string>

class UiLanguage : public Service {
public:
    using Service::Service;
    void OnReady() override;
    const wchar_t* Text(std::string_view key) const;
    std::wstring Format(std::string_view key,
                        std::initializer_list<cerf::i18n::MessageArgument> arguments) const;
    const std::string& Language() const { return catalog_.Language(); }

private:
    cerf::i18n::TranslationCatalog catalog_;
    std::map<std::string, std::wstring, std::less<>> wide_messages_;
};
