#include "guest_calibration_warning.h"
#include "ui_language.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../socs/guest_cpu_reset.h"
#include "guest_calibration_warning_dialog.h"
#include "host_balloon_hint.h"
#include "host_window.h"
#include "pointer_input.h"
#include "pointer_router.h"
#include "pointer_source.h"
#include "pointer_widget.h"

REGISTER_SERVICE(GuestCalibrationWarning);

namespace {
constexpr UINT kSwitchBackHoldMs = 5000;
}

bool GuestCalibrationWarning::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void GuestCalibrationWarning::OnReady() {
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
        if (!present_.exchange(false)) return;
        emu_.Get<HostWindow>().RunOnUiThread([this] { EndCycle(); });
    });
}

PointerSource* GuestCalibrationWarning::StockSource() {
    PointerSource* ga = &emu_.Get<PointerInput>();
    for (auto* s : emu_.Get<PointerRouter>().Sources())
        if (s != ga) return s;
    return nullptr;
}

void GuestCalibrationWarning::OnCalibrationAppeared() {
    if (present_.exchange(true)) return;
    LOG(GuestAdditions, "[CALIB] guest calibration window appeared\n");
    emu_.Get<HostWindow>().RunOnUiThread([this] { ShowWarning(); });
}

void GuestCalibrationWarning::OnCalibrationDisappeared() {
    if (!present_.exchange(false)) return;
    LOG(GuestAdditions, "[CALIB] guest calibration window disappeared\n");
    emu_.Get<HostWindow>().RunOnUiThread([this] { EndCycle(); });
}

void GuestCalibrationWarning::ShowWarning() {
    if (emu_.Get<GuestCalibrationWarningDialog>().Show() !=
        CalibWarningChoice::SwitchToStock)
        return;

    PointerSource* stock = StockSource();
    if (!stock) {
        LOG(Caution, "[CALIB] no stock pointing device to switch to\n");
        return;
    }
    emu_.Get<PointerRouter>().SetActive(stock);
    switched_to_stock_ = true;
    LOG(GuestAdditions, "[CALIB] switched to stock input on user request\n");
}

void GuestCalibrationWarning::EndCycle() {
    emu_.Get<GuestCalibrationWarningDialog>().Dismiss();
    if (!switched_to_stock_) return;
    switched_to_stock_ = false;

    auto& router = emu_.Get<PointerRouter>();
    router.RearmAutoSelect();
    if (router.Active() != &emu_.Get<PointerInput>()) {
        LOG(GuestAdditions, "[CALIB] calibration over; the Guest Additions "
            "pointer is not ready, keeping the stock device\n");
        return;
    }
    LOG(GuestAdditions, "[CALIB] switched back to the Guest Additions pointer\n");
    emu_.Get<HostBalloonHint>().ShowUnderWidget(
        &emu_.Get<PointerWidget>(),
        emu_.Get<UiLanguage>().Text("calibration.switched_back_to_the_guest_additions_mouse_pointer"),
        kSwitchBackHoldMs);
}
