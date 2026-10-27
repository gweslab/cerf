#define NOMINMAX
#include <windows.h>
#include <shellapi.h>

#include <host_branch_table.h>

#include "../cerf-qt/install_root_files.h"
#include "../cerf-qt/product_links.h"

#include <cerfcore/core/ascii_wide_text.h>
#include <cerfcore/core/path_split.h>
#include <cerfcore/core/text_append.h>

namespace {

using cerfcore::AppendText;
using cerfcore::AsciiWideText;

constexpr AsciiWideText kFrontend(host_branch_table::kKeylessFrontend);
constexpr AsciiWideText kUninstaller(cerffrontend::kUninstallerFileName);
constexpr AsciiWideText kTitle(cerffrontend::kProductName);
constexpr AsciiWideText kDownloadUrl(cerffrontend::kDownloadUrl.text);
constexpr wchar_t  kUninstallFlag[] = L"--uninstall";

constexpr int kMessageCapacity = MAX_PATH + 128;

const wchar_t* SkipProgramName(const wchar_t* cmd) {
    if (*cmd == L'"') {
        ++cmd;
        while (*cmd && *cmd != L'"') ++cmd;
        if (*cmd) ++cmd;
        return cmd;
    }
    while (*cmd && *cmd != L' ' && *cmd != L'\t') ++cmd;
    return cmd;
}

[[noreturn]] void Fail(const wchar_t* text) {
    MessageBoxW(nullptr, text, kTitle.text, MB_OK | MB_ICONERROR);
    ExitProcess(1);
}

bool HasUninstallFlag() {
    int     count = 0;
    bool    found = false;
    LPWSTR* argv  = CommandLineToArgvW(GetCommandLineW(), &count);
    if (argv == nullptr) Fail(L"The command line could not be read.");
    for (int i = 1; i < count; ++i)
        if (lstrcmpW(argv[i], kUninstallFlag) == 0) found = true;
    LocalFree(argv);
    return found;
}

}

extern "C" void __stdcall StubEntry() {
    wchar_t        exe[MAX_PATH];
    wchar_t        message[kMessageCapacity];
    const DWORD    len    = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    const wchar_t* target = HasUninstallFlag() ? kUninstaller.text : kFrontend.text;

    if (len == 0 || len >= MAX_PATH) {
        message[0] = L'\0';
        AppendText(message, kTitle.text);
        AppendText(message, L" could not find its own location.");
        Fail(message);
    }
    exe[cerfcore::PathNameOffset(exe, len, cerfcore::kWindowsPathSeparators<wchar_t>)] = L'\0';
    if (!AppendText(exe, target)) Fail(L"The installation path is too long.");

    const wchar_t*    tail = SkipProgramName(GetCommandLineW());
    const std::size_t size = std::size_t(lstrlenW(exe)) + std::size_t(lstrlenW(tail)) + 3;
    auto*             cmd  = static_cast<wchar_t*>(HeapAlloc(GetProcessHeap(), 0, size * sizeof(wchar_t)));
    if (cmd == nullptr) Fail(L"Out of memory.");
    cmd[0] = L'\0';
    AppendText(cmd, size, L"\"");
    AppendText(cmd, size, exe);
    AppendText(cmd, size, L"\"");
    AppendText(cmd, size, tail);

    STARTUPINFOW        si;
    PROCESS_INFORMATION pi;
    SecureZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    SecureZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(exe, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        message[0] = L'\0';
        AppendText(message, target);
        AppendText(message, L" could not be started. Re-download CERF from ");
        AppendText(message, kDownloadUrl.text);
        Fail(message);
    }

    AllowSetForegroundWindow(pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    ExitProcess(0);
}
