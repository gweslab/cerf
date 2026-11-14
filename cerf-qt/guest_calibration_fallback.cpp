#include "guest_calibration_fallback.h"

#include "balloon_hint.h"
#include "calibration_warning_prompt.h"
#include "cerfman/property_fields.h"
#include "live_property_sheet.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/host/auto_calibration.h>
#include <cerfcore/host/pointer_widget.h>

namespace cerffrontend {

namespace {

constexpr uint32_t kSwitchBackHoldMs = 5000;

}

REGISTER_SERVICE(GuestCalibrationFallback);

bool GuestCalibrationFallback::ShouldRegister() { return emu_.Get<cerfcore::DeviceConfig>().guest_additions; }

void GuestCalibrationFallback::Show() {
    switch (emu_.Get<CalibrationWarningPrompt>().Show()) {
        case CalibWarningChoice::kSwitchToStock: emu_.Get<cerfcore::AutoCalibration>().SwitchToStockPointer(); return;
        case CalibWarningChoice::kChangeResolution:
            emu_.Get<LivePropertySheet>().Open(sheet_page::kGuestAdditions, true, [this](bool accepted) {
                if (!accepted && emu_.Get<cerfcore::AutoCalibration>().GuestAdditionsCalibrationShown()) Show();
            });
            return;
        case CalibWarningChoice::kDismissed: return;
    }
}

void GuestCalibrationFallback::EndCycle(bool pointer_switched_back) {
    emu_.Get<CalibrationWarningPrompt>().Dismiss();
    if (!pointer_switched_back) return;
    emu_.Get<BalloonHint>().ShowUnderWidget(&emu_.Get<cerfcore::PointerWidget>(),
                                            "Switched back to the Guest Additions mouse pointer", kSwitchBackHoldMs);
}

}
