#include <cerfcore/host/calibration_notice.h>

#include "balloon_hint.h"
#include "calibration_warning_prompt.h"
#include "frontend_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/pointer_input.h>
#include <cerfcore/host/pointer_router.h>
#include <cerfcore/host/pointer_source.h>
#include <cerfcore/host/pointer_widget.h>
#include <cerfcore/socs/guest_cpu_reset.h>

#include <atomic>

namespace cerffrontend {

namespace {

constexpr uint32_t kSwitchBackHoldMs = 5000;

class GuestCalibrationWarning : public cerfcore::CalibrationNotice {
public:
    using cerfcore::CalibrationNotice::CalibrationNotice;

    bool ShouldRegister() override { return emu_.Get<cerfcore::DeviceConfig>().guest_additions; }

    void OnReady() override {
        emu_.Get<cerfcore::GuestCpuReset>().RegisterResetListener([this](cerfcore::ResetLineKind) {
            if (emu_.Get<cerfcore::GuestCpuReset>().DeliveredResetWasResume()) return;
            if (!present_.exchange(false)) return;
            emu_.Get<FrontendWindow>().RunOnUiThread([this] { EndCycle(); });
        });
    }

    void OnCalibrationAppeared() override {
        if (present_.exchange(true)) return;
        LOG(GuestAdditions, "[CALIB] guest calibration window appeared\n");
        emu_.Get<FrontendWindow>().RunOnUiThread([this] { ShowWarning(); });
    }

    void OnCalibrationDisappeared() override {
        if (!present_.exchange(false)) return;
        LOG(GuestAdditions, "[CALIB] guest calibration window disappeared\n");
        emu_.Get<FrontendWindow>().RunOnUiThread([this] { EndCycle(); });
    }

private:
    cerfcore::PointerSource* StockSource() {
        cerfcore::PointerSource* ga = &emu_.Get<cerfcore::PointerInput>();
        for (auto* s : emu_.Get<cerfcore::PointerRouter>().Sources())
            if (s != ga) return s;
        return nullptr;
    }

    void ShowWarning() {
        if (emu_.Get<CalibrationWarningPrompt>().Show() != CalibWarningChoice::kSwitchToStock)
            return;
        cerfcore::PointerSource* stock = StockSource();
        if (!stock) {
            LOG(Caution, "[CALIB] no stock pointing device to switch to\n");
            return;
        }
        emu_.Get<cerfcore::PointerRouter>().SetActive(stock);
        switched_to_stock_ = true;
        LOG(GuestAdditions, "[CALIB] switched to stock input on user request\n");
    }

    void EndCycle() {
        emu_.Get<CalibrationWarningPrompt>().Dismiss();
        if (!switched_to_stock_) return;
        switched_to_stock_ = false;

        auto& router = emu_.Get<cerfcore::PointerRouter>();
        router.RearmAutoSelect();
        if (router.Active() != &emu_.Get<cerfcore::PointerInput>()) {
            LOG(GuestAdditions, "[CALIB] calibration over; the Guest Additions "
                "pointer is not ready, keeping the stock device\n");
            return;
        }
        LOG(GuestAdditions, "[CALIB] switched back to the Guest Additions pointer\n");
        emu_.Get<BalloonHint>().ShowUnderWidget(&emu_.Get<cerfcore::PointerWidget>(),
                                                "Switched back to the Guest Additions mouse pointer",
                                                kSwitchBackHoldMs);
    }

    std::atomic<bool> present_{false};
    bool              switched_to_stock_ = false;
};

}

REGISTER_SERVICE_AS(GuestCalibrationWarning, cerfcore::CalibrationNotice);

}
