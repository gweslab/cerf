#include "device_actions.h"

#include "bundle_installer.h"
#include "device_directory.h"
#include "device_meta.h"
#include "device_run_state.h"
#include "emulator_launcher.h"
#include "filesystem_path.h"
#include "flow_reply.h"
#include "local_manifest_store.h"
#include "manager_operations.h"
#include "starting_devices.h"

#include <cerfcore/core/cerf_config.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/state/state_image_format.h>
#include "../main_config.h"

#include <QDir>
#include <QStringList>

REGISTER_SERVICE(DeviceActions);

bool DeviceActions::VerboseLogs() const { return cerfcore::Log::GetEnabled() == cerfcore::Log::MASK_ALL; }

void DeviceActions::SetVerboseLogs(bool verbose) {
    if (verbose == VerboseLogs()) return;
    cerfcore::Log::SetEnabled(verbose ? cerfcore::Log::MASK_ALL : cerfcore::Log::MASK_PRODUCTION_DEFAULT);
    emit verboseLogsChanged();
}

bool DeviceActions::Running(const QString& name) const {
    return ReadRunningStatus(LocalManifestStore::DevicePath(name)).has_value() ||
           emu_.Get<StartingDevices>().Pending(name);
}

bool DeviceActions::HasSavedState(const QString& name) const {
    return ReadSavedState(LocalManifestStore::DevicePath(name)).has_value();
}

QString DeviceActions::WarmBoot() const { return QString::fromLatin1(cerfcore::kBootWarm); }

QString DeviceActions::ColdBoot() const { return QString::fromLatin1(cerfcore::kBootCold); }

QVariantMap DeviceActions::Launch(const QString& name, const QString& boot, bool confirmed) {
    if (emu_.Get<StartingDevices>().Pending(name)) return {};
    QStringList args{QString::fromLatin1(cerffrontend::kArgDevice) + name};
    if (VerboseLogs())
        args.append(QString::fromLatin1(cerffrontend::kArgLog) + QString::fromLatin1(cerfcore::Log::kAllCategories));
    args.append(QString::fromLatin1(cerfcore::kArgBoot) +
                (boot.isEmpty() ? QString::fromLatin1(cerfcore::kBootResume) : boot));
    return emu_.Get<EmulatorLauncher>().Launch(name, args, confirmed);
}

QVariantMap DeviceActions::RunningError(const QString& name) const {
    return FlowError(QStringLiteral("Device is running"),
                     QStringLiteral("%1 is running. Close it and try again.").arg(DisplayName(name)));
}

QVariantMap DeviceActions::DiscardSavedState(const QString& name) {
    if (Running(name)) return RunningError(name);
    const QString path = LocalManifestStore::DevicePath(name);
    if (!ReadSavedState(path)) return {};
    for (const char* file : {cerfcore::kDefaultStateFile, cerfcore::kSavedStateScreenshotFile}) {
        QString error;
        if (!RemoveEntry(PathOf(QDir(path).filePath(QString::fromLatin1(file))), error))
            return FlowError(QStringLiteral("Delete failed"),
                             QStringLiteral("Could not delete the saved state:\n%1").arg(error));
    }
    return {};
}

QVariantMap DeviceActions::Remove(const QString& name) {
    if (Running(name)) return RunningError(name);
    emu_.Get<ManagerOperations>().RunDeletion(name, emu_.Get<BundleInstaller>().Delete(name));
    return {};
}

QString DeviceActions::Directory(const QString& name) const { return LocalManifestStore::DevicePath(name); }

QString DeviceActions::DisplayName(const QString& name) const {
    return DeviceDirectory(LocalManifestStore::DevicePath(name)).ReadMeta().meta.DisplayNameOr(name);
}

QString DeviceActions::RelativePath(const QString& name) const { return LocalManifestStore::RelativeDevicePath(name); }

QString DeviceActions::Rename(const QString& name, const QString& display_name) {
    QString error;
    if (!DeviceDirectory(LocalManifestStore::DevicePath(name)).WriteUserName(display_name.trimmed(), error))
        return error;
    emit emu_.Get<ManagerOperations>().devicesChanged();
    return QString();
}
