#include "saved_state_preview.h"

#include "frontend_window.h"
#include "screenshots.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/state/hibernation.h>

#include <string>

namespace cerffrontend {

REGISTER_SERVICE(SavedStatePreview);

void SavedStatePreview::OnReady() {
    emu_.Get<cerfcore::Hibernation>().RegisterSavedListener([this](const std::string&) {
        const std::string preview =
            cerfcore::GetDeviceDir(emu_.Get<cerfcore::DeviceConfig>().device_name) + kSavedStatePreviewFile;
        emu_.Get<FrontendWindow>().RunOnUiThread(
            [this, preview] { emu_.Get<Screenshots>().SaveGuestSurfaceTo(preview); });
    });
}

}
