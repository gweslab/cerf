#include "process_wait.h"
#include "shell_integration_windows.h"
#include "uninstall_dialogs.h"
#include "uninstall_removal.h"

#include <cerfcore/core/cli_option.h>
#include <cerfcore/platform/wide_text_win32.h>
#include "../cerf-qt/cerfman/wait_for_pid.h"
#include "../cerf-qt/install_root_files.h"

#include <commctrl.h>
#include <shellapi.h>

#include <optional>
#include <string>
#include <vector>

namespace {

constexpr char kUninstallDirArg[] = "--uninstall-dir=";

struct Arguments {
    std::optional<std::wstring> install_dir;
    std::optional<uint32_t>     wait_pid;
};

std::optional<Arguments> ParseArguments() {
    Arguments args;
    int       count = 0;
    LPWSTR*   argv  = CommandLineToArgvW(GetCommandLineW(), &count);
    if (argv == nullptr) return std::nullopt;
    for (int i = 1; i < count; ++i) {
        std::optional<uint32_t> pid;
        const wchar_t*          dir = nullptr;
        if (cerfcore::ReadCliOption<wchar_t>(argv[i], kUninstallDirArg, dir)) args.install_dir = dir;
        else if (ParseWaitForPidArg(argv[i], pid)) args.wait_pid = pid;
    }
    LocalFree(argv);
    return args;
}

std::wstring QuoteArgument(const std::wstring& argument) {
    std::wstring quoted = L"\"";
    size_t       slashes = 0;
    for (const wchar_t c : argument) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        quoted.append(c == L'"' ? slashes * 2 + 1 : slashes, L'\\');
        slashes = 0;
        quoted.push_back(c);
    }
    quoted.append(slashes * 2, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

bool MakeTempDirectory(std::wstring& out, DWORD& error) {
    wchar_t temp[MAX_PATH + 1] = {};
    if (GetTempPathW(MAX_PATH + 1, temp) == 0) {
        error = GetLastError();
        return false;
    }
    for (DWORD attempt = 0;; ++attempt) {
        wchar_t name[64] = {};
        std::swprintf(name, 64, L"cerf-uninstall-%lu-%lu", GetCurrentProcessId(), GetTickCount() + attempt);
        out = shell_integration::JoinPath(temp, name);
        if (CreateDirectoryW(out.c_str(), nullptr)) return true;
        error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) return false;
    }
}

int FailTempStart(DWORD error) {
    ShowError(nullptr, L"The uninstaller cannot start from the temporary folder:\n" + shell_integration::ErrorText(error));
    return 1;
}

int RelaunchFromTemp() {
    const std::wstring self = shell_integration::ExecutablePath();
    std::wstring       temp;
    DWORD              error = ERROR_SUCCESS;
    if (self.empty()) error = GetLastError();
    if (self.empty() || !MakeTempDirectory(temp, error)) return FailTempStart(error);
    const std::wstring target =
        shell_integration::JoinPath(temp, cerfcore::Utf8ToWide(cerffrontend::kUninstallerFileName));
    std::wstring command = QuoteArgument(target) + L" " +
                           QuoteArgument(cerfcore::Utf8ToWide(kUninstallDirArg) + shell_integration::DirectoryOf(self)) +
                           L" " +
                           cerfcore::Utf8ToWide(WaitForPidArgument(GetCurrentProcessId()).c_str());
    STARTUPINFOW        startup = {};
    PROCESS_INFORMATION process = {};
    startup.cb                  = sizeof(startup);
    if (!CopyFileW(self.c_str(), target.c_str(), FALSE) ||
        !CreateProcessW(target.c_str(), command.data(), nullptr, nullptr, FALSE, 0, nullptr, temp.c_str(), &startup,
                        &process))
        return FailTempStart(GetLastError());
    AllowSetForegroundWindow(process.dwProcessId);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return 0;
}

bool WaitForInstallationProcesses(const std::wstring& install_dir, int& exit_code) {
    for (;;) {
        std::vector<uint32_t> pids;
        std::wstring          error;
        if (!process_wait::ProcessesRunningFrom(install_dir, pids, error)) {
            ShowError(nullptr, error);
            exit_code = 1;
            return false;
        }
        if (pids.empty()) return true;
        if (!AskRetry(nullptr, L"The emulator is running",
                      shell_integration::ProductName() +
                          L" is running and its files cannot be replaced while it is.\n\nClose every emulator "
                          L"window, then retry.")) {
            exit_code = 0;
            return false;
        }
    }
}

bool WaitForHandoff(uint32_t pid) {
    std::wstring error;
    if (process_wait::WaitForPidExit(pid, kWaitForPidTimeoutMs, error)) return true;
    if (error.empty())
        error = L"the uninstaller (pid " + std::to_wstring(pid) + L") is still running after " +
                std::to_wstring(kWaitForPidTimeoutMs / 1000) + L" s; its files cannot be removed";
    ShowError(nullptr, error);
    return false;
}

int Uninstall(HINSTANCE instance, const Arguments& args) {
    const std::wstring  install_dir = *args.install_dir;
    const ConfirmResult confirm     = RunConfirmDialog(instance, install_dir);
    if (!confirm.accepted) return 0;
    if (args.wait_pid && !WaitForHandoff(*args.wait_pid)) return 1;
    int exit_code = 0;
    if (!WaitForInstallationProcesses(install_dir, exit_code)) return exit_code;

    const OwnedIntegration owned = FindOwnedIntegration(install_dir);
    RunProgressDialog(instance, [&](const ProgressSink& sink) {
        const RemovalHost host{[&](const std::wstring& line) { sink.Log(line); },
                               [&](const std::wstring& title, const std::wstring& message) {
                                   return sink.AskRetry(title, message);
                               }};
        sink.Log(L"Removing " + install_dir);
        std::vector<std::wstring> left = RemoveInstallation(install_dir, confirm.delete_user_data, host);
        for (const std::wstring& name : RemoveShellIntegration(owned, host)) left.push_back(name);
        if (left.empty()) {
            sink.Finish(shell_integration::ProductName() + L" has been uninstalled");
            return;
        }
        sink.Log(L"");
        std::wstring left_line = L"Left behind: ";
        for (size_t i = 0; i < left.size(); ++i) left_line += (i == 0 ? L"" : L", ") + left[i];
        sink.Log(left_line);
        sink.Finish(shell_integration::ProductName() + L" was only partly removed");
    });
    return 0;
}

}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    INITCOMMONCONTROLSEX controls = {sizeof(controls), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);
    const std::optional<Arguments> args = ParseArguments();
    if (!args) {
        ShowError(nullptr, L"The command line could not be read.");
        return 1;
    }
    if (!args->install_dir) return RelaunchFromTemp();
    return Uninstall(instance, *args);
}
