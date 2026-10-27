#define NOMINMAX

#include "utf8_arguments.h"

#include <cerfcore/core/log.h>
#include <cerfcore/core/product_name.h>
#include <cerfcore/platform/wide_text_win32.h>

#include <windows.h>

#include <shellapi.h>

std::vector<std::string> Utf8Arguments(int, char**) {
    int     count = 0;
    LPWSTR* wide  = CommandLineToArgvW(GetCommandLineW(), &count);
    if (wide == nullptr) {
        MessageBoxW(nullptr, L"The command line could not be read.",
                    cerfcore::Utf8ToWide(cerfcore::kProductName).c_str(), MB_OK | MB_ICONERROR);
        cerfcore::CerfFatalExit(cerfcore::CERF_FATAL_USER_ERROR);
    }
    std::vector<std::string> arguments;
    for (int i = 0; i < count; ++i) arguments.push_back(cerfcore::WideToUtf8(wide[i]));
    LocalFree(wide);
    return arguments;
}
