#pragma once

#include "string_utils.h"

#include <windows.h>

#include <string>

inline std::string WindowsErrorText(DWORD code) {
    wchar_t* buf = nullptr;
    const DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                       FORMAT_MESSAGE_IGNORE_INSERTS,
                                   nullptr, code, 0, reinterpret_cast<wchar_t*>(&buf), 0, nullptr);
    std::wstring text = (n && buf) ? std::wstring(buf, n) : std::wstring();
    if (buf) LocalFree(buf);
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' ||
                             text.back() == L' '  || text.back() == L'.'))
        text.pop_back();
    const std::string code_text = "Windows error " + std::to_string(code);
    return text.empty() ? code_text : WideToUtf8(text) + " (" + code_text + ")";
}
