#pragma once

#include "message_format.h"

#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace cerf::i18n {

class TranslationCatalog {
public:
    std::vector<std::string> Load(const std::filesystem::path& directory,
                                   const std::string& language);
    const std::string& Text(std::string_view key) const;
    std::string Format(std::string_view key,
                        std::initializer_list<MessageArgument> arguments) const;
    const std::map<std::string, std::string, std::less<>>& Messages() const { return messages_; }
    const std::string& Language() const { return language_; }

private:
    std::map<std::string, std::string, std::less<>> messages_;
    std::string language_ = "en";
};

}
