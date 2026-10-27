#define NOMINMAX

#include "crash_report.h"

#include "../process_mode.h"
#include "../product_links.h"

#include <cerfcore/core/ascii_wide_text.h>
#include <cerfcore/core/product_name.h>
#include <cerfcore/core/text_append.h>
#include <cerfcore/platform/host_process.h>
#include <cerfcore/platform/wide_text_win32.h>

#include <windows.h>

#include <string>

namespace {

using cerfcore::AppendText;
using cerfcore::AsciiWideText;

constexpr AsciiWideText kTitle(cerfcore::kProductName);
constexpr AsciiWideText kArgument(kCrashReportArg);
constexpr AsciiWideText kFeedback(cerffrontend::kFeedbackUrl.text);

wchar_t g_executable[MAX_PATH];

bool StartCrashWindow(const wchar_t* log) {
    wchar_t command[2 * MAX_PATH + 64] = {};
    AppendText(command, L"\"");
    AppendText(command, g_executable);
    AppendText(command, L"\" \"");
    AppendText(command, kArgument.text);
    AppendText(command, log);
    AppendText(command, L"\"");
    STARTUPINFOW        startup{};
    PROCESS_INFORMATION process{};
    startup.cb = sizeof(startup);
    if (!CreateProcessW(g_executable, command, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &process))
        return false;
    AllowSetForegroundWindow(process.dwProcessId);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return true;
}

}

void QtCrashReport::Prepare() {
    const std::wstring path = cerfcore::Utf8ToWide(cerfcore::host_platform::ExecutablePath().c_str());
    AppendText(g_executable, path.c_str());
}

void QtCrashReport::Present(const char* log_file) {
    wchar_t log[MAX_PATH] = {};
    MultiByteToWideChar(CP_UTF8, 0, log_file, -1, log, MAX_PATH);
    if (StartCrashWindow(log)) return;
    wchar_t text[MAX_PATH + 256] = {};
    AppendText(text, kTitle.text);
    AppendText(text, L" stopped on an unexpected error. Log: ");
    AppendText(text, log);
    AppendText(text, L"\n\nIf you think this is a bug - open ");
    AppendText(text, kFeedback.text);
    AppendText(text, L" and file a bug report");
    MessageBoxW(nullptr, text, kTitle.text, MB_OK | MB_ICONERROR | MB_TASKMODAL | MB_TOPMOST);
}
