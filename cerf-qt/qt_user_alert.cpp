#include <cerfcore/host/user_alert.h>

#include "alert_display.h"
#include "frontend_window.h"
#include "qt_ui_thread_calls.h"

#include <cerfcore/core/cerf_emulator.h>

namespace {

class QtUserAlert : public cerfcore::UserAlert {
public:
    using cerfcore::UserAlert::UserAlert;

    void Show(cerfcore::AlertLevel level, cerfcore::AlertPlacement placement, const std::string& title,
              const std::string& text) override {
        emu_.Get<QtUiThreadCalls>().Run(
            [this, level, placement, title, text] { emu_.Get<AlertDisplay>().Show(level, placement, title, text); });
    }

    void Post(cerfcore::AlertLevel level, const std::string& title, const std::string& text,
              std::function<void()> after) override {
        emu_.Get<cerffrontend::FrontendWindow>().RunOnUiThread([this, level, title, text, after] {
            emu_.Get<AlertDisplay>().Show(level, cerfcore::AlertPlacement::kStandalone, title, text);
            if (after) after();
        });
    }
};

}

REGISTER_SERVICE_AS(QtUserAlert, cerfcore::UserAlert);
