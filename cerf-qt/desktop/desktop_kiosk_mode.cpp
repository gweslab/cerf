#include "../frontend_window.h"
#include "../kiosk_mode.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

namespace {

class DesktopKioskMode : public cerffrontend::KioskMode {
public:
    using cerffrontend::KioskMode::KioskMode;

    void CloseRequested(std::function<void()>) override { LOG(Manager, "KioskMode: close request refused\n"); }

protected:
    void Lock() override {
        auto& window = emu_.Get<cerffrontend::FrontendWindow>();
        if (!window.IsFullscreen()) window.ToggleFullscreen();
    }

    void Unlock() override {
        auto& window = emu_.Get<cerffrontend::FrontendWindow>();
        if (window.IsFullscreen()) window.ToggleFullscreen();
    }
};

}

REGISTER_SERVICE_AS(DesktopKioskMode, cerffrontend::KioskMode);
