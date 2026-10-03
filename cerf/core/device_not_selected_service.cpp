#define NOMINMAX

#include "device_not_selected_service.h"

#include "cerf_emulator.h"
#include "log.h"

#include <windows.h>

REGISTER_SERVICE(DeviceNotSelectedService);

void DeviceNotSelectedService::Halt(const std::string& global_config_path) {
    LOG(Caution, "device is blank: set \"device\" in %s or pass --device=NAME\n",
        global_config_path.c_str());

#if !CERF_DEV_MODE
    MessageBoxW(nullptr,
                L"No device is selected. CERF will exit.\n\nStart a device from CE Runtime "
                L"Foundation Launcher, or start cerf.exe with --device=NAME.",
                L"No device - CE Runtime Foundation",
                MB_OK | MB_ICONERROR);
#endif

    CerfFatalExit(CERF_FATAL_USER_ERROR);
}
