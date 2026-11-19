#include "calibration_answers.h"
#include "frontend_window.h"
#include "guest_calibration_fallback.h"
#include "qt_ui_thread_calls.h"
#include "yes_no_prompt.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/calibration_host.h>
#include <cerfcore/host/notification_stack.h>
#include <cerfcore/host/user_alert.h>

#include <QMetaObject>
#include <QPointer>

#include <chrono>
#include <optional>
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

    cerfcore::CalibrationAnswer ApprovesCalibration() override {
        return AskYes(CalibrationQuestion::kCalibrate, 0, 0, "Calibrate the screen for you?");
    }

    cerfcore::CalibrationAnswer ApprovesPanelResolution(uint32_t width, uint32_t height) override {
        return AskYes(CalibrationQuestion::kPanelResolution, width, height,
                      "You need a stock resolution to pass the calibration screen. Switch and soft reset now?");
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
    cerfcore::CalibrationAnswer AskYes(CalibrationQuestion question, uint32_t width, uint32_t height,
                                       const std::string& message) {
        CalibrationAnswers* answers = emu_.TryGet<CalibrationAnswers>();
        PromptAnswer        prompt  = PromptAnswer::kClosed;
        std::optional<bool> remote;
        ui_calls_->Run([&] {
            QPointer<QObject> dialog;
            const auto        close = [&dialog] {
                if (dialog) QMetaObject::invokeMethod(dialog.data(), "close");
            };
            if (answers != nullptr) answers->Opened(question, width, height, [&remote, &close](bool yes) {
                remote = yes;
                close();
            });
            prompt = emu_.Get<YesNoPrompt>().Ask(kTitle, message, YesNoLevel::kPlain, YesNoEnter::kYes,
                                                 [&dialog, &remote, &close](QObject* opened) {
                                                     dialog = opened;
                                                     if (remote) close();
                                                 });
            if (answers != nullptr) answers->Closed();
        });
        if (remote) return cerfcore::CalibrationAnswer{.yes = *remote, .host_notices = false};
        return cerfcore::CalibrationAnswer{.yes = prompt == PromptAnswer::kYes, .host_notices = true};
    }

    QtUiThreadCalls* ui_calls_ = nullptr;
    FrontendWindow*  window_   = nullptr;
};

}

REGISTER_SERVICE_AS(QtCalibrationHost, cerfcore::CalibrationHost);

}
