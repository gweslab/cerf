#include "guest_calibration_fallback.h"

#include "balloon_hint.h"
#include "bar_widgets.h"
#include "calibration_warning_prompt.h"
#include "cerfman/property_fields.h"
#include "live_property_sheet.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/host/machine_guest_calibration.h>
#include <cerfcore/host/machine_object_tree.h>
#include <cerfcore/host/pointer_router.h>

namespace cerffrontend {

namespace {

constexpr uint32_t kSwitchBackHoldMs = 5000;

}

REGISTER_SERVICE(GuestCalibrationFallback);

bool GuestCalibrationFallback::ShouldRegister() { return emu_.Get<cerfcore::DeviceConfig>().guest_additions; }

cerfcore::MachineGuestCalibration* GuestCalibrationFallback::FindIn(const cerfcore::MachineObject* parent) {
    for (cerfcore::MachineObject* object : emu_.Get<cerfcore::MachineObjectTree>().Children(parent)) {
        if (auto* window = dynamic_cast<cerfcore::MachineGuestCalibration*>(object)) return window;
        if (auto* window = FindIn(object)) return window;
    }
    return nullptr;
}

void GuestCalibrationFallback::Show() {
    switch (emu_.Get<CalibrationWarningPrompt>().Show()) {
        case CalibWarningChoice::kSwitchToStock: FindIn(nullptr)->SwitchToStockPointer(); return;
        case CalibWarningChoice::kChangeResolution:
            emu_.Get<LivePropertySheet>().Open(sheet_page::kGuestAdditions, true, [this](bool accepted) {
                if (!accepted && FindIn(nullptr)->Shown()) Show();
            });
            return;
        case CalibWarningChoice::kDismissed: return;
    }
}

void GuestCalibrationFallback::EndCycle(bool pointer_switched_back) {
    emu_.Get<CalibrationWarningPrompt>().Dismiss();
    if (!pointer_switched_back) return;
    emu_.Get<BalloonHint>().ShowUnderWidget(emu_.Get<BarWidgets>().ForObject(&emu_.Get<cerfcore::PointerRouter>()),
                                            "Switched back to the Guest Additions mouse pointer", kSwitchBackHoldMs);
}

}
