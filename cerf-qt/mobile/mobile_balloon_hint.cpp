#include "../balloon_hint.h"

#include "mobile_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QString>

namespace {

class MobileBalloonHint : public cerffrontend::BalloonHint {
public:
    using cerffrontend::BalloonHint::BalloonHint;

    void ShowUnderWidget(const cerfcore::HostWidget*, const std::string& text, uint32_t hold_ms) override {
        Show(text, hold_ms);
    }

    void ShowUnderCaptureWidget(const std::string& text, uint32_t hold_ms) override { Show(text, hold_ms); }

private:
    void Show(const std::string& text, uint32_t hold_ms) {
        emu_.Get<MobileEmulatorWindow>().ShowHint(QString::fromStdString(text), hold_ms, kCanvasBottomGap);
    }
};

}

REGISTER_SERVICE_AS(MobileBalloonHint, cerffrontend::BalloonHint);
