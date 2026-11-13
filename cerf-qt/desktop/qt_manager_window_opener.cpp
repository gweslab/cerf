#include "qt_manager_window_opener.h"

#include "../cerfman/property_sheets.h"
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
    QMetaObject::invokeMethod(emu_.Get<QtEmulatorWindow>().Window(), "openSettings",
                              Q_ARG(QVariant, QString::fromLatin1(page)),
                              Q_ARG(QVariant, QString::fromStdString(device_line)));
}

void QtManagerWindowOpener::OpenTutorial() {
    QMetaObject::invokeMethod(emu_.Get<QtEmulatorWindow>().Window(), "openTutorial");
}

void QtManagerWindowOpener::EditLiveProperties(const char* page, bool force_reboot, std::optional<int> ce_major,
                                               cerffrontend::LiveSheetFinished finished) {
    emu_.Get<PropertySheets>().EditLive(Placement(), QString::fromLatin1(page), force_reboot, ce_major,
                                        std::move(finished));
}

QVariantMap QtManagerWindowOpener::Placement() const {
    return {{QStringLiteral("transientParent"),
             QVariant::fromValue(static_cast<QWindow*>(emu_.Get<QtEmulatorWindow>().Window()))},
            {QStringLiteral("visible"), true}};
}
