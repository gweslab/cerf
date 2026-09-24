#define NOMINMAX

#include "device_not_found_service.h"

#include "cerf_emulator.h"
#include "device_config.h"
#include "log.h"
#include "cerf_paths.h"
#include "string_utils.h"

#include "../boot/sec_flash.h"
#include "../socs/imx51/imx51_nand_store.h"

#include <windows.h>

#include <string>

REGISTER_SERVICE(DeviceNotFoundService);

namespace {

bool FileExists(const std::string& path) {
    DWORD a = ::GetFileAttributesW(Utf8ToWide(path.c_str()).c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

}

bool DeviceNotFoundService::ShouldRegister() { return !IsDevicePresent(); }

bool DeviceNotFoundService::IsDevicePresent() {
    const auto& cfg = emu_.Get<DeviceConfig>();
    if (!cfg.rom_primary.empty() &&
        FileExists(ResolveDeviceFile(cfg.device_name, cfg.rom_primary)))
        return true;
    if (auto* sf = emu_.TryGet<SecFlash>(); sf && sf->IsPresent()) return true;
    return emu_.TryGet<Imx51NandStore>() != nullptr;
}

void DeviceNotFoundService::EnsureFound() {
    const auto& cfg = emu_.Get<DeviceConfig>();
    LOG(Caution, "device '%s' has no ROM on disk\n", cfg.device_name.c_str());

#if !CERF_DEV_MODE
    const std::wstring text =
        L"Device \"" + Utf8ToWide(cfg.device_name.c_str()) +
        L"\" has no ROM on disk.\n\nOpen CE Runtime Foundation Launcher to install it.";
    MessageBoxW(nullptr, text.c_str(),
                L"Device not found - CE Runtime Foundation",
                MB_OK | MB_ICONERROR);
#endif

    CerfFatalExit(CERF_FATAL_USER_ERROR);
}
