#include "translation_catalog.h"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4244)
#endif
#include <yaml-cpp/yaml.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <fstream>
#include <stdexcept>

namespace cerf::i18n {
namespace {

constexpr size_t kMaxCatalogBytes = 1024 * 1024;

std::string Scalar(const YAML::Node& node) {
    if (!node.IsScalar() ||
        (node.Tag() != "?" && node.Tag() != "!" &&
         node.Tag() != "tag:yaml.org,2002:str"))
        throw std::invalid_argument("Catalog values must be text");
    const std::string value = node.Scalar();
    if (value.find('\0') != std::string::npos)
        throw std::invalid_argument("NUL in catalog text");
    return value;
}

std::map<std::string, YAML::Node> Mapping(const YAML::Node& node) {
    if (!node.IsMap() || (node.Tag() != "?" && node.Tag() != "!" &&
                         node.Tag() != "tag:yaml.org,2002:map"))
        throw std::invalid_argument("Catalog must be a mapping");
    std::map<std::string, YAML::Node> result;
    for (const auto& entry : node) {
        const auto key = Scalar(entry.first);
        if (!result.emplace(key, entry.second).second)
            throw std::invalid_argument("Duplicate catalog key: " + key);
    }
    return result;
}

std::map<std::string, std::string, std::less<>> ReadCatalog(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open language catalog");
    std::string content(kMaxCatalogBytes + 1, '\0');
    file.read(content.data(), static_cast<std::streamsize>(content.size()));
    content.resize(static_cast<size_t>(file.gcount()));
    if (file.bad() || content.size() > kMaxCatalogBytes)
        throw std::runtime_error("Cannot read language catalog or size exceeds 1 MiB");
    const auto documents = YAML::LoadAll(content);
    if (documents.size() != 1)
        throw std::invalid_argument("Catalog must contain one YAML document");
    const auto root = Mapping(documents.front());
    if (root.size() != 2 || !root.contains("name") || !root.contains("messages") ||
        Scalar(root.at("name")).empty())
        throw std::invalid_argument("Catalog requires name and messages");
    std::map<std::string, std::string, std::less<>> result;
    for (const auto& [key, node] : Mapping(root.at("messages"))) {
        if (key.empty()) throw std::invalid_argument("Empty message key");
        result.emplace(key, Scalar(node));
    }
    return result;
}

}

std::vector<std::string> TranslationCatalog::Load(
    const std::filesystem::path& directory, const std::string& language) {
    if (!IsLanguageCode(language)) throw std::invalid_argument("Invalid language code");
    auto messages = ReadCatalog(directory / "en.yml");
    if (messages.empty()) throw std::invalid_argument("English catalog is empty");
    for (const auto& [key, value] : messages) MessageParameters(value);
    std::vector<std::string> warnings;
    std::string selected = "en";
    if (language != "en") {
        try {
            const auto translations = ReadCatalog(directory / (language + ".yml"));
            for (const auto& [key, value] : translations) {
                const auto original = messages.find(key);
                if (original == messages.end()) {
                    warnings.push_back("Unknown message: " + key);
                    continue;
                }
                try {
                    if (MessageParameters(value) != MessageParameters(original->second))
                        throw std::invalid_argument("Placeholder mismatch");
                    original->second = value;
                } catch (const std::invalid_argument& error) {
                    warnings.push_back(key + ": " + error.what());
                }
            }
            selected = language;
        } catch (const std::exception& error) {
            warnings.push_back(language + ": " + error.what());
        }
    }
    messages_ = std::move(messages);
    language_ = std::move(selected);
    return warnings;
}

const std::string& TranslationCatalog::Text(std::string_view key) const {
    const auto found = messages_.find(key);
    if (found == messages_.end()) throw std::out_of_range("Unknown message: " + std::string(key));
    return found->second;
}

std::string TranslationCatalog::Format(std::string_view key,
                                      std::initializer_list<MessageArgument> arguments) const {
    return RenderMessage(Text(key), arguments);
}

}
