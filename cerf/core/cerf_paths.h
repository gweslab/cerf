#pragma once
#include <string>

#include "string_utils.h"

inline std::wstring GetCerfExePath() {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        const DWORD n = ::GetModuleFileNameW(NULL, &buf[0], (DWORD)buf.size());
        if (n == 0) return {};
        if (n < buf.size()) {
            buf.resize(n);
            return buf;
        }
        if (buf.size() >= 32768) return {};
        buf.resize(buf.size() * 2);
    }
}

inline std::string GetCerfDir() {
    const std::wstring ws = GetCerfExePath();
    size_t sep = ws.find_last_of(L"\\/");
    if (sep == std::wstring::npos) return "";
    return WideToUtf8(ws.substr(0, sep + 1));
}

/* Device directory: "<exe dir>devices\<name>\". */
inline std::string GetDeviceDir(const std::string& device_name) {
    return GetCerfDir() + "devices\\" + device_name + "\\";
}

inline bool IsAbsoluteHostPath(const std::string& path) {
    if (path.size() >= 2 && path[1] == ':') return true;
    return !path.empty() && (path[0] == '\\' || path[0] == '/');
}

inline std::string ResolveDeviceFile(const std::string& device_name,
                                     const std::string& filename) {
    if (IsAbsoluteHostPath(filename)) return filename;
    return GetDeviceDir(device_name) + filename;
}
