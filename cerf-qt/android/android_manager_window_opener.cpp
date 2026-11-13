#include "../manager_windows.h"

#include "../cerfman/property_sheets.h"
#include "../qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/device_config.h>

#include <QVariant>
#include <QVariantMap>
#include <QWindow>

#include <string>

namespace {

class AndroidManagerWindowOpener : public cerffrontend::ManagerWindows {
public:
    using cerffrontend::ManagerWindows::ManagerWindows;

    bool EditLiveProperties(const char* page, bool force_reboot, std::optional<int> ce_major,
                            cerffrontend::GuestReset& reset) override {
        const std::string dir = cerfcore::GetDeviceDir(emu_.Get<cerfcore::DeviceConfig>().device_name);
        const QVariantMap window{{QStringLiteral("mobile"), true},
                                 {QStringLiteral("visibility"), QVariant::fromValue(QWindow::Maximized)}};
        const bool        accepted = emu_.Get<PropertySheets>().EditLive(
            window, QString::fromStdString(dir), QString::fromLatin1(page), force_reboot, ce_major, reset);
        emu_.Get<QtEmulatorWindow>().Raise();
        return accepted;
    }
};

}

REGISTER_SERVICE_AS(AndroidManagerWindowOpener, cerffrontend::ManagerWindows);
