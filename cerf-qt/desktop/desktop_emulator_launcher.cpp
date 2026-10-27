#include "../cerfman/emulator_launcher.h"

#include "../cerfman/device_run_state.h"
#include "../cerfman/flow_reply.h"
#include "../cerfman/local_manifest_store.h"
#include "emulator_raise.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/platform/host_process.h>

#include <QDir>
#include <QProcess>

namespace {

class DesktopEmulatorLauncher : public EmulatorLauncher {
public:
    using EmulatorLauncher::EmulatorLauncher;

    QVariantMap Launch(const QString& name, const QStringList& args, bool) override {
        if (const std::optional<RunningStatus> status = ReadRunningStatus(LocalManifestStore::DevicePath(name))) {
            if (!RaiseEmulatorWindow(*status))
                return FlowError(QStringLiteral("Show CERF"),
                                 QStringLiteral("%1 is running but its window could not be focused.").arg(name));
            return {};
        }
        const QString executable = QString::fromStdString(cerfcore::host_platform::ExecutablePath());
        if (!QProcess::startDetached(executable, args, QString::fromStdString(cerfcore::GetCerfDir())))
            return FlowError(QStringLiteral("Launch failed"),
                             QStringLiteral("%1 could not be started.").arg(QDir::toNativeSeparators(executable)));
        return StartedReply(name);
    }
};

}

REGISTER_SERVICE_AS(DesktopEmulatorLauncher, EmulatorLauncher);
