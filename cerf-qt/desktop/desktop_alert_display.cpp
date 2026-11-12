#include "../alert_display.h"
#include "../cerfman/manager_engine.h"
#include "../nested_event_loops.h"
#include "../qml_dialog_waiter.h"
#include "../qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QQuickWindow>
#include <QString>
#include <QVariant>
#include <QVariantMap>
#include <QWindow>

namespace {

class DesktopAlertDisplay final : public AlertDisplay {
public:
    using AlertDisplay::AlertDisplay;

    void Show(cerfcore::AlertLevel level, cerfcore::AlertPlacement placement, const std::string& title,
              const std::string& text) override {
        QVariantMap properties{{QStringLiteral("title"), QString::fromStdString(title)},
                               {QStringLiteral("message"), QString::fromStdString(text)},
                               {QStringLiteral("level"), level == cerfcore::AlertLevel::kError
                                                             ? QStringLiteral("error")
                                                             : QStringLiteral("warning")},
                               {QStringLiteral("topmost"), placement == cerfcore::AlertPlacement::kTopmost}};
        if (placement == cerfcore::AlertPlacement::kOverWindow)
            properties.insert(QStringLiteral("transientParent"),
                              QVariant::fromValue(static_cast<QWindow*>(emu_.Get<QtEmulatorWindow>().Window())));
        properties.insert(QStringLiteral("visible"), true);
        QmlDialogWaiter waiter;
        waiter.Watch(emu_.Get<ManagerEngine>().Open(QStringLiteral("AlertWindow"), properties));
        waiter.Wait(emu_.Get<NestedEventLoops>());
    }
};

}

REGISTER_SERVICE_AS(DesktopAlertDisplay, AlertDisplay);
