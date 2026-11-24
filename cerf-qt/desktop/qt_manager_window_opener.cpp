#include "qt_manager_window_opener.h"

#include "../cerfman/property_sheets.h"
#include "../password_gated_actions.h"
#include "../qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QMetaObject>
#include <QQuickWindow>
#include <QString>
#include <QVariant>
#include <QWindow>

#include <utility>

REGISTER_SERVICE(QtManagerWindowOpener);

void QtManagerWindowOpener::OpenSettings(const char* page, const std::string& device_line) {
    emu_.Get<cerffrontend::PasswordGatedActions>().OpenCerfman([this, page = std::string(page), device_line] {
        QMetaObject::invokeMethod(emu_.Get<QtEmulatorWindow>().Window(), "openSettings",
                                  Q_ARG(QVariant, QString::fromStdString(page)),
                                  Q_ARG(QVariant, QString::fromStdString(device_line)));
    });
}

void QtManagerWindowOpener::OpenTutorial() {
    emu_.Get<cerffrontend::PasswordGatedActions>().OpenCerfman(
        [this] { QMetaObject::invokeMethod(emu_.Get<QtEmulatorWindow>().Window(), "openTutorial"); });
}

void QtManagerWindowOpener::EditLiveProperties(const char* page, bool force_reboot, bool live_resize,
                                               cerffrontend::LiveSheetFinished finished) {
    emu_.Get<PropertySheets>().EditLive(Placement(), QString::fromLatin1(page), force_reboot, live_resize,
                                        std::move(finished));
}

QVariantMap QtManagerWindowOpener::Placement() const {
    return {{QStringLiteral("transientParent"),
             QVariant::fromValue(static_cast<QWindow*>(emu_.Get<QtEmulatorWindow>().Window()))},
            {QStringLiteral("visible"), true}};
}
