#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"
#include <fstream>
#include <cstring>

/* String conversion helpers (duplicated from registry_impl.cpp — static, trivial) */

static std::wstring NarrowToWide(const std::string& s) {
    std::wstring w;
    for (char c : s) w += (wchar_t)(unsigned char)c;
    return w;
}

static std::wstring ToLowerW(const std::wstring& s) {
    std::wstring r = s;
    for (auto& c : r) if (c >= L'A' && c <= L'Z') c += 32;
    return r;
}

/* Map REGEDIT4 root names to our abbreviated forms */
static std::wstring MapRegRoot(const std::wstring& key) {
    if (key.substr(0, 18) == L"HKEY_CLASSES_ROOT\\") return L"HKCR\\" + key.substr(18);
    if (key == L"HKEY_CLASSES_ROOT") return L"HKCR";
    if (key.substr(0, 18) == L"HKEY_CURRENT_USER\\") return L"HKCU\\" + key.substr(18);
    if (key == L"HKEY_CURRENT_USER") return L"HKCU";
    if (key.substr(0, 19) == L"HKEY_LOCAL_MACHINE\\") return L"HKLM\\" + key.substr(19);
    if (key == L"HKEY_LOCAL_MACHINE") return L"HKLM";
    if (key.substr(0, 11) == L"HKEY_USERS\\") return L"HKU\\" + key.substr(11);
    if (key == L"HKEY_USERS") return L"HKU";
    return key;
}

/* Parse a value from a .reg file value string (after the '=').
   Handles: "string", dword:XXXX, hex:XX,XX,... */
static bool ParseRegFileValue(const std::string& rest, Win32Thunks::RegValue& val) {
    if (rest.empty()) return false;
    if (rest[0] == '"') {
        /* String value: "content" */
        size_t end = rest.find('"', 1);
        if (end == std::string::npos) return false;
        val.type = REG_SZ;
        std::string raw = rest.substr(1, end - 1);
        /* Unescape \\  -> \ */
        std::wstring ws;
        for (size_t i = 0; i < raw.size(); i++) {
            if (raw[i] == '\\' && i + 1 < raw.size() && raw[i+1] == '\\') { ws += L'\\'; i++; }
            else ws += (wchar_t)(unsigned char)raw[i];
        }
        val.data.resize((ws.size() + 1) * 2);
        memcpy(val.data.data(), ws.c_str(), val.data.size());
        return true;
    } else if (rest.substr(0, 6) == "dword:") {
        val.type = REG_DWORD;
        uint32_t dw = (uint32_t)strtoul(rest.substr(6).c_str(), nullptr, 16);
        val.data.resize(4);
        memcpy(val.data.data(), &dw, 4);
        return true;
    } else if (rest.substr(0, 4) == "hex:") {
        val.type = REG_BINARY;
        std::string hex = rest.substr(4);
        for (size_t i = 0; i < hex.size(); ) {
            while (i < hex.size() && (hex[i] == ',' || hex[i] == ' ' || hex[i] == '\\' || hex[i] == '\r' || hex[i] == '\n')) i++;
            if (i + 1 < hex.size() && isxdigit(hex[i]) && isxdigit(hex[i+1])) {
                val.data.push_back((uint8_t)strtoul(hex.substr(i, 2).c_str(), nullptr, 16));
                i += 2;
            } else break;
        }
        return true;
    }
    return false;
}

void Win32Thunks::ImportRegFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return;
    std::wstring current_key;
    std::string line;
    size_t key_count = 0;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == ';') continue;
        if (line == "REGEDIT4" || line == "Windows Registry Editor Version 5.00") continue;

        /* Key: [HKEY_...] */
        if (line[0] == '[' && line.back() == ']') {
            current_key = MapRegRoot(NarrowToWide(line.substr(1, line.size() - 2)));
            registry[current_key];
            EnsureParentKeys(current_key);
            key_count++;
            continue;
        }
        if (current_key.empty()) continue;

        /* Default value: @="..." or @=dword:... */
        std::wstring val_name;
        std::string val_str;
        if (line.size() >= 2 && line[0] == '@' && line[1] == '=') {
            val_name = L"";
            val_str = line.substr(2);
        } else if (line[0] == '"') {
            size_t eq = line.find("\"=");
            if (eq == std::string::npos || eq < 1) continue;
            val_name = NarrowToWide(line.substr(1, eq - 1));
            val_str = line.substr(eq + 2);
        } else continue;

        RegValue val = {};
        if (ParseRegFileValue(val_str, val))
            registry[current_key].values[val_name] = val;
    }
    LOG(REG, "[REG] Imported %zu keys from %s\n", key_count, path.c_str());
}
