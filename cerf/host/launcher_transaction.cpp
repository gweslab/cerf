#define NOMINMAX
#include "launcher_transaction.h"

#include "../core/cerf_emulator.h"
#include "../core/cerf_paths.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../core/string_utils.h"

#include <cstdio>
#include <fstream>

REGISTER_SERVICE(LauncherTransaction);

namespace {

constexpr wchar_t kLauncherExe[] = L"launcher\\launcher.exe";
constexpr wchar_t kTitle[]       = L"CERF configuration";

}

void LauncherTransaction::Complain(HWND owner, const std::wstring& text) {
    LOG(Caution, "LauncherTransaction: %ls\n", text.c_str());
    MessageBoxW(owner, text.c_str(), kTitle, MB_OK | MB_ICONERROR);
}

bool LauncherTransaction::LocateLauncher(HWND owner, std::wstring& exe) {
    exe = Utf8ToWide(GetCerfDir().c_str()) + kLauncherExe;
    const DWORD attrs = GetFileAttributesW(exe.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES &&
        (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
        return true;
    Complain(owner, L"The launcher is missing, so the configuration window "
                    L"cannot open.\n\n" + exe);
    return false;
}

bool LauncherTransaction::WriteRequest(HWND owner, const std::string& path,
                                       const nlohmann::json& request) {
    std::ofstream f(path, std::ios::trunc | std::ios::binary);
    if (f.is_open()) {
        f << request.dump(2) << '\n';
        if (f.good()) return true;
    }
    Complain(owner, L"CERF could not write its request for the configuration "
                    L"window.\n\n" + Utf8ToWide(path.c_str()));
    return false;
}

void LauncherTransaction::PumpUntilExit(HANDLE process) {
    for (;;) {
        const DWORD r = MsgWaitForMultipleObjects(1, &process, FALSE, INFINITE,
                                                  QS_ALLINPUT);
        if (r != WAIT_OBJECT_0 + 1) return;
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                PostQuitMessage((int)msg.wParam);
                return;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

bool LauncherTransaction::Spawn(HWND owner, const std::wstring& exe,
                                const std::string& device,
                                const std::string& file) {
    wchar_t owner_arg[24];
    _snwprintf_s(owner_arg, _TRUNCATE, L"%llu",
                 (unsigned long long)(uintptr_t)owner);
    std::wstring cmd = L"\"" + exe + L"\" transactional \"" +
                       Utf8ToWide(device.c_str()) + L"\" \"" +
                       Utf8ToWide(file.c_str()) + L"\" " + owner_arg;
    const std::wstring cwd = Utf8ToWide(GetCerfDir().c_str());

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE, 0, nullptr,
                        cwd.c_str(), &si, &pi)) {
        wchar_t code[32];
        _snwprintf_s(code, _TRUNCATE, L"%lu", GetLastError());
        Complain(owner, L"CERF could not start the configuration window "
                        L"(launcher.exe error " + std::wstring(code) +
                        L").\n\n" + exe);
        return false;
    }
    CloseHandle(pi.hThread);

    AllowSetForegroundWindow(pi.dwProcessId);
    PumpUntilExit(pi.hProcess);
    if (GetForegroundWindow() != owner) SetForegroundWindow(owner);

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    if (exit_code == 0) return true;

    wchar_t code[32];
    _snwprintf_s(code, _TRUNCATE, L"%lu", exit_code);
    Complain(owner, L"The configuration window closed with an error (exit "
                    L"code " + std::wstring(code) + L").");
    return false;
}

bool LauncherTransaction::ReadResponse(HWND owner, const std::string& path,
                                       const char* key,
                                       nlohmann::json& response) {
    nlohmann::json parsed;
    {
        std::ifstream f(path);
        if (!f.is_open()) {
            Complain(owner, L"The configuration window left no answer "
                            L"behind.\n\n" + Utf8ToWide(path.c_str()));
            return false;
        }
        try {
            f >> parsed;
        } catch (const std::exception&) {
            Complain(owner, L"CERF could not read the answer from the "
                            L"configuration window.\n\n" +
                                Utf8ToWide(path.c_str()));
            return false;
        }
    }
    if (!parsed.is_object() || !parsed.contains(key)) return true;
    const auto& block = parsed[key];
    if (!block.is_object() || !block.contains("response")) return true;
    const auto& answer = block["response"];
    if (answer.is_object()) response = answer;
    return true;
}

bool LauncherTransaction::Run(HWND owner, const char* scaffolding,
                              const nlohmann::json& query,
                              nlohmann::json& response) {
    if (running_) return false;
    running_ = true;

    std::wstring exe;
    bool ok = LocateLauncher(owner, exe);
    if (ok) {
        nlohmann::json request;
        request[scaffolding]["query"] = query;

        const std::string device = emu_.Get<DeviceConfig>().device_name;
        char file[64];
        _snprintf_s(file, _TRUNCATE, "transactional-%08lX-%04X.json",
                    GetCurrentProcessId(), ++serial_);
        const std::string path = GetDeviceDir(device) + file;

        ok = WriteRequest(owner, path, request);
        if (ok) {
            ok = Spawn(owner, exe, device, file);
            if (ok) ok = ReadResponse(owner, path, scaffolding, response);
            DeleteFileW(Utf8ToWide(path.c_str()).c_str());
        }
    }

    running_ = false;
    return ok;
}
