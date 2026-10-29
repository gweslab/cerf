#include "qt_manager_window_opener.h"

#include "../cerfman/manager_engine.h"
#include "../cerfman/property_sheets.h"
#include "../cerfman/settings_pages.h"
#include "qt_main_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/device_config.h>

#include <QVariant>
#include <QWidget>
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

bool QtManagerWindowOpener::EditLiveCustomizations(bool force_reboot, std::optional<int> ce_major,
                                                   cerffrontend::GuestReset& reset) {
    const std::string dir = cerfcore::GetDeviceDir(emu_.Get<cerfcore::DeviceConfig>().device_name);
    return emu_.Get<PropertySheets>().EditLive(Placement(), QString::fromStdString(dir), force_reboot, ce_major,
                                               reset);
}

QVariantMap QtManagerWindowOpener::Placement() const {
    return {{QStringLiteral("transientParent"),
             QVariant::fromValue(emu_.Get<QtMainWindow>().Window()->windowHandle())},
            {QStringLiteral("visible"), true}};
}
