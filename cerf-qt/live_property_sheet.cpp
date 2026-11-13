#include "live_property_sheet.h"

#include "cerfman/property_sheets.h"
#include "frontend_window.h"
#include "guest_additions_ui_policy.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/device_config_refresh.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_customizations_reset.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_framebuffer.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_resize.h>
#include <cerfcore/state/shutdown_action.h>

#include <QString>

#include <optional>
#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(LivePropertySheet);

void LivePropertySheet::Open(const char* page, bool force_reboot, Done done) {
    if (emu_.Get<PropertySheets>().ShowLive(QString::fromLatin1(page), force_reboot)) {
        if (done) waiters_->push_back(std::move(done));
        return;
    }
    std::optional<int> ce_major;
    uint16_t           major = 0, minor = 0;
    if (emu_.Get<GuestAdditionsUiPolicy>().CeVersion(major, minor)) ce_major = major;

    waiters_ = std::make_shared<Waiters>();
    if (done) waiters_->push_back(std::move(done));
    emu_.Get<ManagerWindows>().EditLiveProperties(
        page, force_reboot, ce_major, gate_.Bind([this, waiters = waiters_](bool accepted, GuestReset reset) {
            emu_.Get<FrontendWindow>().RunOnUiThread(
                [this, waiters, accepted, reset] { Finish(accepted, reset, *waiters); });
        }));
}

void LivePropertySheet::Finish(bool accepted, GuestReset reset, const Waiters& waiters) {
    if (accepted) {
        const auto&    cfg    = emu_.Get<cerfcore::DeviceConfig>();
        const uint32_t prev_w = cfg.board_configurable_screen_width;
        const uint32_t prev_h = cfg.board_configurable_screen_height;
        emu_.Get<cerfcore::DeviceConfigRefresh>().Refresh();
        if (cfg.guest_additions) ApplyGuestAdditions(reset, prev_w, prev_h);
    }
    for (const Done& done : waiters) done(accepted);
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
