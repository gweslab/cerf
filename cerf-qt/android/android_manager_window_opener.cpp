#include "../manager_windows.h"

#include "../cerfman/property_sheets.h"
#include "../qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_gate.h>

#include <QVariant>
#include <QVariantMap>
#include <QWindow>

#include <utility>

namespace {

class AndroidManagerWindowOpener : public cerffrontend::ManagerWindows {
public:
    using cerffrontend::ManagerWindows::ManagerWindows;

    void EditLiveProperties(const char* page, bool force_reboot, std::optional<int> ce_major,
                            cerffrontend::LiveSheetFinished finished) override {
        const QVariantMap window{{QStringLiteral("mobile"), true},
                                 {QStringLiteral("visibility"), QVariant::fromValue(QWindow::Maximized)}};
        emu_.Get<PropertySheets>().EditLive(
            window, QString::fromLatin1(page), force_reboot, ce_major,
            gate_.Bind([this, finished = std::move(finished)](bool accepted, cerffrontend::GuestReset reset) {
                emu_.Get<QtEmulatorWindow>().Raise();
                finished(accepted, reset);
            }));
    }

private:
    const cerfcore::InstanceGate gate_{emu_};
};

}

REGISTER_SERVICE_AS(AndroidManagerWindowOpener, cerffrontend::ManagerWindows);
