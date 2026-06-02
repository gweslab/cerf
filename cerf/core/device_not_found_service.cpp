#define NOMINMAX

#include "cerf_emulator.h"
#include "device_config.h"
#include "log.h"
#include "service.h"
#include "string_utils.h"

#include <windows.h>

#include <string>
#include <vector>

namespace {

/* Registers only when the resolved device has no ROM on disk. Production
   builds ask the user (download / open launcher / cancel); dev builds skip
   the modal and auto-download so automation never blocks. When the ROM is
   present this service takes no slot at all. */
class DeviceNotFoundService : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override { return !IsDevicePresent(); }

    void OnReady() override {
        const auto& cfg = emu_.Get<DeviceConfig>();
        LOG(Caution, "device '%s' has no ROM on disk\n",
            cfg.device_name.c_str());

#if CERF_DEV_MODE
        /* Dev/automation runs cannot answer a modal — treat as "yes, download". */
        SpawnLauncherFetch(cfg.device_name);
#else
        const int choice = PromptDownload(cfg.device_name);
        bool ok = true;
        if      (choice == IDYES) ok = SpawnLauncherFetch(cfg.device_name);
        else if (choice == IDNO)  ok = SpawnLauncherApp();
        /* IDCANCEL: exit, do nothing. */
        if ((choice == IDYES || choice == IDNO) && !ok)
            MessageBoxA(nullptr,
                        "launcher.exe could not be started. Make sure it sits "
                        "next to cerf.exe.",
                        "CERF: launcher missing", MB_OK | MB_ICONERROR);
#endif
        CerfFatalExit(CERF_FATAL_USER_ERROR);
    }

private:
    static bool FileExists(const std::string& path) {
        DWORD a = ::GetFileAttributesW(Utf8ToWide(path.c_str()).c_str());
        return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
    }

    static bool DirHasRom(const std::string& dir) {
        WIN32_FIND_DATAW fd;
        const wchar_t* pats[] = { L"*.nb0", L"*.bin" };
        for (const wchar_t* pat : pats) {
            std::wstring glob = Utf8ToWide(dir.c_str()) + pat;
            HANDLE h = ::FindFirstFileW(glob.c_str(), &fd);
            if (h != INVALID_HANDLE_VALUE) { ::FindClose(h); return true; }
        }
        return false;
    }

    bool IsDevicePresent() {
        const auto& cfg = emu_.Get<DeviceConfig>();
        const std::string dir = GetCerfDir() + "devices/" + cfg.device_name + "/";
        if (!cfg.rom_primary.empty())
            return FileExists(dir + cfg.rom_primary);
        return DirHasRom(dir);
    }

    /* MB_YESNOCANCEL: Yes = download + relaunch, No = open launcher GUI,
       Cancel = exit. cerfos gets the Demo OS wording; others name the id. */
    static int PromptDownload(const std::string& device) {
        std::string msg;
        if (device == "cerfos") {
            msg = "Would you like to download Demo OS (~2 MB) and launch it?"
                  "\n\n";
        } else {
            msg = "Device '" + device + "' is not found. Would you like to "
                  "attempt to download it via Launcher app and restart CERF?"
                  "\n\n";
        }
        msg += "Otherwise, would you like to just open Launcher app (press No) "
               "or exit and do nothing (Cancel)?";
        return MessageBoxA(nullptr, msg.c_str(), "CERF: device not found",
                           MB_YESNOCANCEL | MB_ICONQUESTION);
    }

    static bool SpawnLauncher(const std::wstring& args) {
        const std::string launcher = GetCerfDir() + "launcher.exe";
        if (!FileExists(launcher))
            return false;

        std::wstring cmd = L"\"" + Utf8ToWide(launcher.c_str()) + L"\"";
        if (!args.empty()) cmd += L" " + args;
        std::wstring cwd = Utf8ToWide(GetCerfDir().c_str());
        std::vector<wchar_t> mutable_cmd(cmd.begin(), cmd.end());
        mutable_cmd.push_back(L'\0');

        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        BOOL ok = ::CreateProcessW(nullptr, mutable_cmd.data(), nullptr, nullptr,
                                   FALSE, 0, nullptr, cwd.c_str(), &si, &pi);
        if (ok) {
            ::CloseHandle(pi.hThread);
            ::CloseHandle(pi.hProcess);
        }
        return ok != FALSE;
    }

    static bool SpawnLauncherFetch(const std::string& device) {
        LOG(Cerf, "spawning launcher to fetch '%s'\n", device.c_str());
        return SpawnLauncher(L"sync download " + Utf8ToWide(device.c_str())
                             + L" --run-in-cerf");
    }

    static bool SpawnLauncherApp() {
        LOG(Cerf, "opening launcher app\n");
        return SpawnLauncher(L"");
    }
};

}  /* namespace */

REGISTER_SERVICE(DeviceNotFoundService);
