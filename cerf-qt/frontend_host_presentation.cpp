#include <cerfcore/host/host_presentation.h>

#include "boot_screen.h"
#include "frontend_window.h"
#include "screenshots.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/log.h>

namespace cerffrontend {

namespace {

class FrontendHostPresentation : public cerfcore::HostPresentation {
public:
    using cerfcore::HostPresentation::HostPresentation;

    void PanelEnabled() override {
        if (emu_.Get<cerfcore::DeviceConfig>().guest_additions) {
            LOG(Lcd, "HostPresentation::PanelEnabled: guest additions on, the panel "
                "layer does not size the host surface\n");
            return;
        }
        emu_.Get<FrontendWindow>().OnLcdEnabled();
    }

    void GuestRemoded(uint32_t guest_w, uint32_t guest_h) override {
        emu_.Get<FrontendWindow>().NotifyGuestRemoded(guest_w, guest_h);
    }

    uint32_t SurfaceWidth() const override {
        return emu_.Get<FrontendWindow>().GuestSurfaceWidth();
    }

    uint32_t SurfaceHeight() const override {
        return emu_.Get<FrontendWindow>().GuestSurfaceHeight();
    }

    void RestoreSurfaceSize(uint32_t w, uint32_t h) override {
        emu_.Get<FrontendWindow>().RunOnUiThread([this, w, h] {
            auto& window = emu_.Get<FrontendWindow>();
            window.SetGuestSurfaceSize(w, h);
            window.MatchGuestSize();
        });
    }

    void SaveScreenshot(const std::string& path) override {
        emu_.Get<FrontendWindow>().RunOnUiThread(
            [this, path] { emu_.Get<Screenshots>().SaveGuestSurfaceTo(path); });
    }

    void ShowCustomizationsRestart() override {
        emu_.Get<BootScreen>().SetRestartLabel("Applying customizations...");
    }
};

}

REGISTER_SERVICE_AS(FrontendHostPresentation, cerfcore::HostPresentation);

}
