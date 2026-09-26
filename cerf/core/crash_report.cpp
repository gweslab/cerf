#define NOMINMAX
#include "crash_report.h"

#include <windows.h>

namespace {


const char* g_log_override = nullptr;

constexpr wchar_t kTitle[] = L"Unexpected error - CE Runtime Foundation";
constexpr wchar_t kVerb[]  = L"\" transactional-crash";
constexpr wchar_t kFallbackText[] =
    L"Something went severely wrong - emulator has to close and was unable "
    L"to open the feedback dialog.\n\n"
    L"If you think this is a bug - open https://cerf.cx/feedback and file a "
    L"bug report";

void Append(wchar_t* buf, int cap, const wchar_t* tail) {
    const int used = lstrlenW(buf);
    if (used < cap) lstrcpynW(buf + used, tail, cap - used);
}

int ExeDir(wchar_t* out, int cap) {
    const DWORD len = GetModuleFileNameW(nullptr, out, (DWORD)cap);
    if (len == 0 || len >= (DWORD)cap) {
        out[0] = L'\0';
        return 0;
    }
    int cut = 0;
    for (DWORD i = 0; i < len; ++i) {
        if (out[i] == L'\\' || out[i] == L'/') cut = (int)i + 1;
    }
    out[cut] = L'\0';
    return cut;
}

bool Spawn() {
    wchar_t dir[MAX_PATH];
    const int cut = ExeDir(dir, MAX_PATH);
    if (cut == 0) return false;

    wchar_t exe[MAX_PATH];
    lstrcpynW(exe, dir, MAX_PATH);
    lstrcpynW(exe + cut, L"launcher\\launcher.exe", MAX_PATH - cut);
    const DWORD attrs = GetFileAttributesW(exe);
    if (attrs == INVALID_FILE_ATTRIBUTES ||
        (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return false;

    wchar_t log[MAX_PATH] = {};
    if (g_log_override) {
        MultiByteToWideChar(CP_ACP, 0, g_log_override, -1, log, MAX_PATH);
    }

    wchar_t cmd[2 * MAX_PATH + 64];
    cmd[0] = L'\0';
    Append(cmd, ARRAYSIZE(cmd), L"\"");
    Append(cmd, ARRAYSIZE(cmd), exe);
    Append(cmd, ARRAYSIZE(cmd), kVerb);
    if (log[0]) {
        Append(cmd, ARRAYSIZE(cmd), L" \"");
        Append(cmd, ARRAYSIZE(cmd), log);
        Append(cmd, ARRAYSIZE(cmd), L"\"");
    }

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, dir,
                        &si, &pi))
        return false;

    AllowSetForegroundWindow(pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

}  // namespace

void CrashReport::SetLogFileOverride(const char* path) {
    g_log_override = path;
}

void CrashReport::Present() {
    if (Spawn()) return;
    MessageBoxW(nullptr, kFallbackText, kTitle,
                MB_OK | MB_ICONERROR | MB_TASKMODAL | MB_TOPMOST);
}
