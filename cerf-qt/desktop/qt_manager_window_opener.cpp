#include "qt_manager_window_opener.h"

#include "../cerfman/manager_engine.h"
#include "../cerfman/property_sheets.h"
#include "../cerfman/settings_pages.h"
#include "../qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/device_config.h>

#include <QQuickWindow>
#include <QVariant>
#include <QWindow>

REGISTER_SERVICE(QtManagerWindowOpener);

namespace {

constexpr char kSettingsWindow[] = "SettingsWindow";
constexpr char kTutorialWindow[] = "TutorialWindow";

}

void QtManagerWindowOpener::OpenAbout(const std::string& device_line) {
    QVariantMap properties = Placement();
    properties.insert(QStringLiteral("initialPage"), QString::fromLatin1(settings_page::kAbout));
    properties.insert(QStringLiteral("deviceLine"), QString::fromStdString(device_line));
    emu_.Get<ManagerEngine>().Open(QString::fromLatin1(kSettingsWindow), properties);
}

void QtManagerWindowOpener::OpenSettings() {
    emu_.Get<ManagerEngine>().Open(QString::fromLatin1(kSettingsWindow), Placement());
}

void QtManagerWindowOpener::OpenTutorial() {
    emu_.Get<ManagerEngine>().Open(QString::fromLatin1(kTutorialWindow), Placement());
}

bool QtManagerWindowOpener::EditLiveProperties(const char* page, bool force_reboot, std::optional<int> ce_major,
                                               cerffrontend::GuestReset& reset) {
    const std::string dir = cerfcore::GetDeviceDir(emu_.Get<cerfcore::DeviceConfig>().device_name);
    return emu_.Get<PropertySheets>().EditLive(Placement(), QString::fromStdString(dir), QString::fromLatin1(page),
                                               force_reboot, ce_major, reset);
}

QVariantMap QtManagerWindowOpener::Placement() const {
    return {{QStringLiteral("transientParent"),
             QVariant::fromValue(static_cast<QWindow*>(emu_.Get<QtEmulatorWindow>().Window()))},
            {QStringLiteral("visible"), true}};
}
