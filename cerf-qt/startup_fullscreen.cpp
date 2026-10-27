#include "frontend_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/service.h>

namespace cerffrontend {

namespace {

class StartupFullscreen : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override {
        if (!emu_.Get<cerfcore::DeviceConfig>().start_fullscreen) return;
        emu_.Get<FrontendWindow>().RunOnUiThread([this] {
            FrontendWindow& window = emu_.Get<FrontendWindow>();
            if (!window.IsFullscreen()) window.ToggleFullscreen();
        });
    }
};

}

REGISTER_SERVICE(StartupFullscreen);

}
