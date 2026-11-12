#include "../alert_display.h"
#include "../qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QString>
#include <QVariantMap>

namespace {

class AndroidAlertDisplay final : public AlertDisplay {
public:
    using AlertDisplay::AlertDisplay;

    void Show(cerfcore::AlertLevel, cerfcore::AlertPlacement, const std::string& title,
              const std::string& text) override {
        emu_.Get<QtEmulatorWindow>().RunDialog(
            QStringLiteral("FlowDialog"), QVariantMap{{QStringLiteral("title"), QString::fromStdString(title)},
                                                      {QStringLiteral("message"), QString::fromStdString(text)}});
    }
};

}

REGISTER_SERVICE_AS(AndroidAlertDisplay, AlertDisplay);
