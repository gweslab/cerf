#include "live_property_sheet.h"

#include "frontend_window.h"
#include "guest_additions_ui_policy.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/device_config_refresh.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_customizations_reset.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_framebuffer.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_resize.h>
#include <cerfcore/state/shutdown_action.h>

#include <optional>

namespace cerffrontend {

REGISTER_SERVICE(LivePropertySheet);

bool LivePropertySheet::Open(const char* page, bool force_reboot) {
    std::optional<int> ce_major;
    uint16_t           major = 0, minor = 0;
    if (emu_.Get<GuestAdditionsUiPolicy>().CeVersion(major, minor)) ce_major = major;

    auto&          cfg    = emu_.Get<cerfcore::DeviceConfig>();
    const uint32_t prev_w = cfg.board_configurable_screen_width;
    const uint32_t prev_h = cfg.board_configurable_screen_height;

    GuestReset reset = GuestReset::kNone;
    if (!emu_.Get<ManagerWindows>().EditLiveProperties(page, force_reboot, ce_major, reset)) return false;

    emu_.Get<cerfcore::DeviceConfigRefresh>().Refresh();
    if (cfg.guest_additions) ApplyGuestAdditions(reset, prev_w, prev_h);
    return true;
}

void LivePropertySheet::ApplyGuestAdditions(GuestReset reset, uint32_t prev_w, uint32_t prev_h) {
    emu_.Get<cerfcore::CerfVirtCustomizationsReset>().Invalidate();
    auto&          cfg = emu_.Get<cerfcore::DeviceConfig>();
    const uint32_t w   = cfg.board_configurable_screen_width;
    const uint32_t h   = cfg.board_configurable_screen_height;

    auto&      win  = emu_.Get<FrontendWindow>();
    const bool fits = emu_.Get<cerfcore::CerfVirtFramebuffer>().FitsPrimary(w, h, "live customization");
    switch (reset) {
        case GuestReset::kSoft:
            if (fits) {
                win.SetGuestResolution(w, h);
                win.FitToResolution(w, h);
            }
            emu_.Get<cerfcore::ShutdownAction>().Perform(cerfcore::ShutdownChoice::SoftReset);
            return;
        case GuestReset::kHard:
            if (fits) {
                win.SetGuestResolution(w, h);
                win.FitToResolution(w, h);
            }
            emu_.Get<cerfcore::ShutdownAction>().Perform(cerfcore::ShutdownChoice::HardReset);
            return;
        case GuestReset::kNone:
            if (fits && (w != prev_w || h != prev_h)) {
                win.FitToResolution(w, h);
                emu_.Get<cerfcore::CerfVirtResize>().RequestResize(w, h);
            }
            return;
    }
}

}
