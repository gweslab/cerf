#include "device_clone.h"

#include "device_actions.h"
#include "device_replica.h"
#include "filesystem_path.h"
#include "local_manifest_store.h"
#include "manager_operations.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QDir>

#include <optional>

REGISTER_SERVICE(DeviceClone);

QVariantMap DeviceClone::Start(const QString& name, bool personal, bool link, bool rom, bool storage,
                               bool saved_state) {
    const QVariantMap refusal = emu_.Get<DeviceActions>().RefuseRunning(name);
    if (!refusal.isEmpty()) return refusal;
    const QString clone  = LocalManifestStore::UnusedDeviceName(name);
    const QString target = LocalManifestStore::DevicePath(clone);
    const QString shown  = emu_.Get<DeviceActions>().DisplayName(name);
    ReplicaOptions options(personal, link, rom, storage, saved_state);
    options.share_base   = target;
    options.display_name = QStringLiteral("Copy of %1").arg(shown);
    const DeviceReplicaPlan plan = emu_.Get<DeviceReplica>().Plan(LocalManifestStore::DevicePath(name), options);

    std::optional<LocalBundleRecord> record;
    if (link) {
        const LocalManifest installed = emu_.Get<LocalManifestStore>().Snapshot();
        if (const auto found = installed.constFind(name); found != installed.constEnd())
            record = LocalBundleRecord{found->updated_at, found->sha256, {}};
    }

    emu_.Get<ManagerOperations>().Run(
        QStringLiteral("Cloning %1…").arg(shown),
        [this, plan, clone, target, record](const OperationProgress& progress, QString& error) {
            if (EntryExists(PathOf(target))) {
                error = QStringLiteral("%1 already exists.").arg(QDir::toNativeSeparators(target));
                return OperationResult::kFailed;
            }
            if (!MakeDirectory(target, error)) return OperationResult::kFailed;
            OperationResult result = plan.files.Run(target, progress, error);
            if (result == OperationResult::kDone && !DeviceReplica::WriteConfigs(plan, target, error))
                result = OperationResult::kFailed;
            if (result == OperationResult::kDone && record &&
                !emu_.Get<LocalManifestStore>().Update(
                    [&](LocalManifest& manifest) {
                        manifest.insert(clone, *record);
                        return true;
                    },
                    error))
                result = OperationResult::kFailed;
            QString cleanup;
            if (result != OperationResult::kDone && !RemoveEntry(PathOf(target), cleanup))
                error += QLatin1Char('\n') + cleanup;
            return result;
        },
        QStringLiteral("Cloned %1").arg(shown), [this, clone](OperationResult result) {
            if (result == OperationResult::kDone) emit cloned(clone);
        });
    return {};
}
