#include "message_format.h"

#include <map>
#include <stdexcept>

namespace cerf::i18n {
namespace {

bool IsLower(char c) { return c >= 'a' && c <= 'z'; }
bool IsUpper(char c) { return c >= 'A' && c <= 'Z'; }
bool IsDigit(char c) { return c >= '0' && c <= '9'; }

std::string Parameter(std::string_view message, size_t& position) {
    const size_t start = ++position;
    while (position < message.size() && message[position] != '}') ++position;
    const std::string name(message.substr(start, position - start));
    if (position == message.size() || name.empty() || !IsLower(name.front()))
        throw std::invalid_argument("Invalid message placeholder");
    for (char c : name)
        if (!IsLower(c) && !IsDigit(c) && c != '_')
            throw std::invalid_argument("Invalid message placeholder: " + name);
    return name;
}

}

bool IsLanguageCode(std::string_view code) {
    const size_t hyphen = code.find('-');
    const auto base = code.substr(0, hyphen);
    if (base.size() != 2 && base.size() != 3) return false;
    for (char c : base) if (!IsLower(c)) return false;
    if (hyphen == std::string_view::npos) return true;
    const auto region = code.substr(hyphen + 1);
    if (region.size() == 2) {
        for (char c : region) if (!IsUpper(c)) return false;
        return true;
    }
    if (region.size() == 3) {
        for (char c : region) if (!IsDigit(c)) return false;
        return true;
    }
    return false;
}

std::set<std::string> MessageParameters(std::string_view message) {
    std::set<std::string> result;
    for (size_t i = 0; i < message.size(); ++i) {
        const char c = message[i];
        if (c != '{' && c != '}') continue;
        if (i + 1 < message.size() && message[i + 1] == c) { ++i; continue; }
        if (c == '}') throw std::invalid_argument("Unmatched closing brace");
        result.insert(Parameter(message, i));
    }
    return result;
}

std::string RenderMessage(std::string_view message,
                          std::initializer_list<MessageArgument> arguments) {
    const auto required = MessageParameters(message);
    std::map<std::string, std::string_view> values;
    for (const auto& [name, value] : arguments) {
        if (!required.contains(std::string(name)) ||
            !values.emplace(name, value).second)
            throw std::invalid_argument("Unexpected or duplicate message argument");
    }
    if (values.size() != required.size())
        throw std::invalid_argument("Missing message argument");
    std::string result;
    for (size_t i = 0; i < message.size(); ++i) {
        const char c = message[i];
        if (c != '{' && c != '}') { result += c; continue; }
        if (i + 1 < message.size() && message[i + 1] == c) {
            result += c;
            ++i;
        } else {
            result += values.at(Parameter(message, i));
        }
    }
    return result;
}

}
