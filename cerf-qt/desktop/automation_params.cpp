#include "automation_params.h"

namespace cerffrontend {

namespace {

[[noreturn]] void Invalid(const char* name, const char* expected) {
    throw AutomationError(AutomationServer::kInvalidParams, std::string(name) + " must be " + expected);
}

}

const AutomationJson* AutomationParams::Find(const char* name) const {
    const auto it = params_.find(name);
    if (it == params_.end() || it->is_null()) return nullptr;
    return &*it;
}

std::optional<int64_t> AutomationParams::OptionalInteger(const char* name) const {
    const AutomationJson* value = Find(name);
    if (value == nullptr) return std::nullopt;
    if (!value->is_number_integer()) Invalid(name, "a whole number");
    return value->get<int64_t>();
}

int64_t AutomationParams::Integer(const char* name) const {
    const std::optional<int64_t> value = OptionalInteger(name);
    if (!value) Invalid(name, "a whole number");
    return *value;
}

std::optional<bool> AutomationParams::OptionalBoolean(const char* name) const {
    const AutomationJson* value = Find(name);
    if (value == nullptr) return std::nullopt;
    if (!value->is_boolean()) Invalid(name, "true or false");
    return value->get<bool>();
}

bool AutomationParams::Boolean(const char* name) const {
    const std::optional<bool> value = OptionalBoolean(name);
    if (!value) Invalid(name, "true or false");
    return *value;
}

std::optional<std::string> AutomationParams::OptionalString(const char* name) const {
    const AutomationJson* value = Find(name);
    if (value == nullptr) return std::nullopt;
    if (!value->is_string()) Invalid(name, "a string");
    return value->get<std::string>();
}

std::string AutomationParams::String(const char* name) const {
    const std::optional<std::string> value = OptionalString(name);
    if (!value) Invalid(name, "a string");
    return *value;
}

std::vector<std::string> AutomationParams::Strings(const char* name) const {
    const AutomationJson* value = Find(name);
    if (value == nullptr || !value->is_array()) Invalid(name, "an array of strings");
    std::vector<std::string> out;
    for (const AutomationJson& item : *value) {
        if (!item.is_string()) Invalid(name, "an array of strings");
        out.push_back(item.get<std::string>());
    }
    return out;
}

}
