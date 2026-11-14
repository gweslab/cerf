#include "device_export.h"

#include "device_actions.h"
#include "device_directory.h"
#include "device_file_value.h"
#include "device_replica.h"
#include "file_offer.h"
#include "filesystem_path.h"
#include "host_file_copy.h"
#include "local_manifest_store.h"
#include "manager_operations.h"
#include "picked_document.h"
#include "zip_create.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/platform/host_file.h>

#include <QDir>
#include <QStandardPaths>
#include <QTemporaryDir>

REGISTER_SERVICE(DeviceExport);

namespace {

constexpr char kArchiveSuffix[] = ".zip";
constexpr char kArchiveMime[]   = "application/zip";
constexpr char kStagedArchive[] = "archive.zip";

bool EmptyPickedDocument(const QString& destination) {
    uint64_t size = 0;
    return IsDocumentFileValue(destination) &&
           cerfcore::host_platform::HostRegularFileSize(destination.toStdString(), size) && size == 0;
}

bool AddConfig(ZipCreator& zip, const QString& staging, const QString& name, QString& error) {
    return zip.AddFile(name, QDir(staging).filePath(name), error);
}

OperationResult Pack(const DeviceReplicaPlan& plan, const QString& staging, const QString& archive,
                     const QString& label, const OperationProgress& progress, QString& error) {
    ZipCreator zip(archive);
    if (!zip.Open(error) || !AddConfig(zip, staging, DeviceDirectory::BaseConfigName(), error) ||
        (!plan.user.empty() && !AddConfig(zip, staging, DeviceDirectory::UserConfigName(), error)))
        return OperationResult::kFailed;
    for (const DeviceFileCopy::File& file : plan.files.Files())
        if (!zip.AddFile(file.name, file.source, error)) return OperationResult::kFailed;
    return zip.Close(QStringLiteral("Packing %1…").arg(label), progress, error);
}

OperationResult WriteArchive(const DeviceReplicaPlan& plan, const QString& staging, const QString& destination,
                             const QString& label, const OperationProgress& progress, QString& error) {
    if (!DeviceReplica::WriteConfigs(plan, staging, error)) return OperationResult::kFailed;
    if (!IsDocumentFileValue(destination)) return Pack(plan, staging, destination, label, progress, error);
    const QString         archive = QDir(staging).filePath(QString::fromLatin1(kStagedArchive));
    const OperationResult packed  = Pack(plan, staging, archive, label, progress, error);
    if (packed != OperationResult::kDone) return packed;
    return CopyHostFile(archive, destination, progress, error);
}

}

QUrl DeviceExport::SuggestedTarget(const QString& name) const {
    const QString folder = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    return QUrl::fromLocalFile(QDir(folder).filePath(name + QString::fromLatin1(kArchiveSuffix)));
}

void DeviceExport::Discard(const QString& destination) const {
    if (EmptyPickedDocument(destination)) DeletePickedDocument(destination);
}

QVariantMap DeviceExport::Start(const QString& name, const QString& destination, bool personal, bool link, bool rom,
                                bool storage, bool saved_state) {
    const QVariantMap refusal = emu_.Get<DeviceActions>().RefuseRunning(name);
    if (!refusal.isEmpty()) return refusal;
    const ReplicaOptions    options(personal, link, rom, storage, saved_state);
    const DeviceReplicaPlan plan  = emu_.Get<DeviceReplica>().Plan(LocalManifestStore::DevicePath(name), options);
    const QString           label = PathDisplayName(destination);
    const QString           shown   = emu_.Get<DeviceActions>().DisplayName(name);
    const bool              created = EmptyPickedDocument(destination);
    emu_.Get<ManagerOperations>().Run(
        QStringLiteral("Exporting %1…").arg(shown),
        [plan, destination, label, created](const OperationProgress& progress, QString& error) {
            const QString devices = LocalManifestStore::DevicesDir();
            QTemporaryDir staging(QDir(devices).filePath(QStringLiteral(".export_XXXXXX")));
            if (!staging.isValid()) {
                error = QStringLiteral("cannot create a temporary folder in %1 (%2)")
                            .arg(QDir::toNativeSeparators(devices), staging.errorString());
                return OperationResult::kFailed;
            }
            const OperationResult result = WriteArchive(plan, staging.path(), destination, label, progress, error);
            if (result != OperationResult::kDone && created) DeletePickedDocument(destination);
            return result;
        },
        QStringLiteral("Exported %1").arg(shown), [destination](OperationResult result) {
            if (result == OperationResult::kDone && IsDocumentFileValue(destination) &&
                !OfferFile(destination, QString::fromLatin1(kArchiveMime)))
                LOG(Manager, "export: cannot open the share sheet for %s\n", qUtf8Printable(destination));
        });
    return {};
}
