#include "live_property_sheet.h"

#include "cerfman/property_sheets.h"
#include "frontend_window.h"

#include <cerfcore/boot/rom_parser_queries.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/device_config_refresh.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_config_apply.h>

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
    auto*              rom   = emu_.TryGet<cerfcore::RomParserQueries>();
    if (rom && rom->KernelSubsystemVersion(major, minor)) ce_major = major;

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
        const auto& cfg      = emu_.Get<cerfcore::DeviceConfig>();
        const auto  previous = cfg.Live();
        emu_.Get<cerfcore::DeviceConfigRefresh>().Refresh();
        if (cfg.guest_additions)
            emu_.Get<cerfcore::CerfVirtConfigApply>().Apply(reset, previous->board_configurable_screen_width,
                                                            previous->board_configurable_screen_height);
    }
    for (const Done& done : waiters) done(accepted);
}

}
