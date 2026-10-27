#include <cerfcore/host/user_alert.h>

#include "../qt_ui_thread_calls.h"
#include "mobile_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QString>
#include <QVariantMap>

namespace {

class MobileUserAlert : public cerfcore::UserAlert {
public:
    using cerfcore::UserAlert::UserAlert;

    void Show(cerfcore::AlertLevel, cerfcore::AlertPlacement, const std::string& title,
              const std::string& text) override {
        emu_.Get<QtUiThreadCalls>().Run([this, title, text] { ShowOnGuiThread(title, text); });
    }

    void Post(cerfcore::AlertLevel, const std::string& title, const std::string& text,
              std::function<void()> after) override {
        emu_.Get<MobileEmulatorWindow>().RunOnUiThread([this, title, text, after] {
            ShowOnGuiThread(title, text);
            if (after) after();
        });
    }

private:
    void ShowOnGuiThread(const std::string& title, const std::string& text) {
        emu_.Get<MobileEmulatorWindow>().RunDialog(
            QStringLiteral("FlowDialog"), QVariantMap{{QStringLiteral("title"), QString::fromStdString(title)},
                                                      {QStringLiteral("message"), QString::fromStdString(text)}});
    }
};

}

REGISTER_SERVICE_AS(MobileUserAlert, cerfcore::UserAlert);
