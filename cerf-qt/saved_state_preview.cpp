#include "saved_state_preview.h"

#include "frontend_window.h"
#include "qt_ui_thread_calls.h"
#include "screenshots.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/platform/host_file.h>
#include <cerfcore/state/crash_state_saver.h>
#include <cerfcore/state/hibernation.h>

#include <string>

namespace cerffrontend {

REGISTER_SERVICE(SavedStatePreview);

void SavedStatePreview::OnReady() {
    emu_.Get<cerfcore::Hibernation>().RegisterSavedListener([this](const std::string&) {
        const std::string preview = DeviceFile(kSavedStatePreviewFile);
        emu_.Get<FrontendWindow>().RunOnUiThread(
            [this, preview] { emu_.Get<Screenshots>().SaveGuestSurfaceTo(preview); });
    });
    emu_.Get<cerfcore::CrashStateSaver>().RegisterSavedListener([this](const std::string&) { SaveCrashPreview(); });
}

std::string SavedStatePreview::DeviceFile(const char* name) const {
    return cerfcore::ResolveDeviceFile(emu_.Get<cerfcore::DeviceConfig>().device_name, name);
}

void SavedStatePreview::SaveCrashPreview() {
    if (cerfcore::host_platform::HostPathExists(emu_.Get<cerfcore::Hibernation>().DefaultStatePath())) return;
    const std::string preview = DeviceFile(kSavedStatePreviewFile);
    emu_.Get<QtUiThreadCalls>().Run([this, &preview] { emu_.Get<Screenshots>().SaveGuestSurfaceTo(preview); });
}

}
