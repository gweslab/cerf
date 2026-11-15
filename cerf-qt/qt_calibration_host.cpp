#include "frontend_window.h"
#include "guest_calibration_fallback.h"
#include "qt_ui_thread_calls.h"
#include "yes_no_prompt.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/calibration_host.h>
#include <cerfcore/host/notification_stack.h>
#include <cerfcore/host/user_alert.h>

#include <chrono>
#include <string>

namespace cerffrontend {

namespace {

constexpr char                 kTitle[] = "Screen calibration";
constexpr std::chrono::seconds kFinishedCardTimeout{5};

class QtCalibrationHost : public cerfcore::CalibrationHost {
public:
    using cerfcore::CalibrationHost::CalibrationHost;

    void OnReady() override {
        ui_calls_ = &emu_.Get<QtUiThreadCalls>();
        window_   = &emu_.Get<FrontendWindow>();
    }

    bool ApprovesCalibration() override { return AskYes("Calibrate the screen for you?"); }

    bool ApprovesPanelResolution(uint32_t, uint32_t) override {
        return AskYes("You need a stock resolution to pass the calibration screen. Switch and soft reset now?");
    }


    void CalibrationFinished() override {
        emu_.Get<cerfcore::NotificationStack>().Post(cerfcore::NotificationKind::Success,
                                                     "Calibration attempt finished", kFinishedCardTimeout);
    }

    void CalibrationFailed() override {
        emu_.Get<cerfcore::UserAlert>().Show(cerfcore::AlertLevel::kError, cerfcore::AlertPlacement::kOverWindow,
                                             kTitle,
                                             "Automatic calibration was unable to find the calibration data on screen");
    }

    void GuestCalibrationUnhandled() override {
        window_->RunOnUiThread([this] { emu_.Get<GuestCalibrationFallback>().Show(); });
    }

    void GuestCalibrationEnded(bool guest_pointer_restored) override {
        window_->RunOnUiThread(
            [this, guest_pointer_restored] { emu_.Get<GuestCalibrationFallback>().EndCycle(guest_pointer_restored); });
    }

private:
    bool AskYes(const std::string& message) {
        PromptAnswer answer = PromptAnswer::kClosed;
        ui_calls_->Run(
            [&] { answer = emu_.Get<YesNoPrompt>().Ask(kTitle, message, YesNoLevel::kPlain, YesNoEnter::kYes); });
        return answer == PromptAnswer::kYes;
    }

    QtUiThreadCalls* ui_calls_ = nullptr;
    FrontendWindow*  window_   = nullptr;
};

}

REGISTER_SERVICE_AS(QtCalibrationHost, cerfcore::CalibrationHost);

}
