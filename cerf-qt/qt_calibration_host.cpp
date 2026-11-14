#include "frontend_window.h"
#include "guest_calibration_fallback.h"
#include "qt_ui_thread_calls.h"
#include "yes_no_prompt.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/calibration_host.h>

namespace cerffrontend {

namespace {

class QtCalibrationHost : public cerfcore::CalibrationHost {
public:
    using cerfcore::CalibrationHost::CalibrationHost;

    void OnReady() override {
        ui_calls_ = &emu_.Get<QtUiThreadCalls>();
        window_   = &emu_.Get<FrontendWindow>();
    }

    cerfcore::FrameGrab CaptureSurface(cerfcore::CalibrationFrame& frame) override {
        bool captured = false;
        if (!ui_calls_->Run([&] { captured = window_->CaptureGuestSurface(frame.pixels, frame.width, frame.height); }))
            return cerfcore::FrameGrab::kClosed;
        return captured ? cerfcore::FrameGrab::kCaptured : cerfcore::FrameGrab::kNoFrame;
    }

    cerfcore::PromptAnswer Confirm(const std::string& title, const std::string& message) override {
        cerfcore::PromptAnswer answer = cerfcore::PromptAnswer::kClosed;
        ui_calls_->Run([&] { answer = emu_.Get<YesNoPrompt>().Ask(title, message, YesNoLevel::kPlain, YesNoEnter::kYes); });
        return answer;
    }

    bool RunConfigurationJob(const std::function<void()>& job) override { return ui_calls_->Run(job); }

    void ShowFallback() override {
        window_->RunOnUiThread([this] { emu_.Get<GuestCalibrationFallback>().Show(); });
    }

    void EndFallback(bool pointer_switched_back) override {
        window_->RunOnUiThread(
            [this, pointer_switched_back] { emu_.Get<GuestCalibrationFallback>().EndCycle(pointer_switched_back); });
    }

private:
    QtUiThreadCalls* ui_calls_ = nullptr;
    FrontendWindow*  window_   = nullptr;
};

}

REGISTER_SERVICE_AS(QtCalibrationHost, cerfcore::CalibrationHost);

}
