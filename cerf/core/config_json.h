#pragma once

#include "log.h"
#include "string_utils.h"

#include <nlohmann/json.hpp>

#include <fstream>
#include <string>

[[noreturn]] inline void CfgFatal(const std::string& path,
                                  const std::string& msg) {
    LOG(Caution, "FATAL: '%s' %s\n", path.c_str(), msg.c_str());
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

inline nlohmann::json CfgReadJsonFile(const std::string& path) {
    std::ifstream f(Utf8ToWide(path.c_str()));
    if (!f.is_open()) return nlohmann::json();
    nlohmann::json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        CfgFatal(path, std::string("JSON parse error: ") + e.what());
    }
    if (!j.is_object())
        CfgFatal(path, "top-level value must be a JSON object");
    return j;
}

inline std::string CfgReadOptString(const nlohmann::json& obj, const char* key,
                                    const std::string& path,
                                    const std::string& ctx) {
    if (!obj.contains(key)) return {};
    const auto& v = obj[key];
    if (v.is_null()) return {};
    if (!v.is_string())
        CfgFatal(path, ctx + "." + key + " must be a string (or null)");
    return v.get<std::string>();
}

inline int CfgReadOptInt(const nlohmann::json& obj, const char* key,
                         const std::string& path, const std::string& ctx) {
    if (!obj.contains(key)) return 0;
    const auto& v = obj[key];
    if (v.is_null()) return 0;
    if (!v.is_number_integer())
        CfgFatal(path, ctx + "." + key + " must be an integer");
    return v.get<int>();
}

inline bool CfgReadOptBool(const nlohmann::json& obj, const char* key,
                           const std::string& path, const std::string& ctx) {
    if (!obj.contains(key)) return false;
    const auto& v = obj[key];
    if (v.is_null()) return false;
    if (!v.is_boolean())
        CfgFatal(path, ctx + "." + key + " must be a boolean");
    return v.get<bool>();
}
