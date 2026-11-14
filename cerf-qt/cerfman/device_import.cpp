#include "device_import.h"

#include "bundle_name.h"
#include "bundle_repositories.h"
#include "device_directory.h"
#include "file_access.h"
#include "filesystem_path.h"
#include "json_file.h"
#include "local_manifest_store.h"
#include "manager_operations.h"
#include "zip_extract.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <memory>

REGISTER_SERVICE(DeviceImport);

namespace {

constexpr char kFallbackName[] = "device";

bool ValidConfig(const QString& root, const QString& name, bool required, QString& error) {
    QFile file(QDir(root).filePath(name));
    if (!file.exists()) {
        if (!required) return true;
        error = QStringLiteral("The archive does not contain %1.").arg(name);
        return false;
    }
    if (!file.open(QIODevice::ReadOnly)) {
        error = QStringLiteral("%1: %2").arg(name, file.errorString());
        return false;
    }
    return ParseJsonObject(file.readAll(), name, error).has_value();
}

OperationResult ImportArchive(const QString& source, const QString& label, const QString& base, QString& name,
                              const OperationProgress& progress, QString& error) {
    const QString devices = LocalManifestStore::DevicesDir();
    if (!MakeDirectory(devices, error)) return OperationResult::kFailed;
    QTemporaryDir staging(QDir(devices).filePath(QStringLiteral(".import_XXXXXX")));
    if (!staging.isValid()) {
        error = QStringLiteral("cannot create a temporary folder in %1 (%2)")
                    .arg(QDir::toNativeSeparators(devices), staging.errorString());
        return OperationResult::kFailed;
    }
    const QString extract = staging.filePath(QStringLiteral("extract"));
    if (!MakeDirectory(extract, error)) return OperationResult::kFailed;
    const OperationResult extracted = ExtractPickedArchive(source, staging.path(), extract, label, progress, error);
    if (extracted != OperationResult::kDone) return extracted;
    const QString root = PreparedBundleRoot(extract);
    QString       problem;
    if (!ValidConfig(root, DeviceDirectory::BaseConfigName(), true, problem) ||
        !ValidConfig(root, DeviceDirectory::UserConfigName(), false, problem)) {
        error = QStringLiteral("%1 is not an exported device.\n\n%2").arg(label, problem);
        return OperationResult::kFailed;
    }
    name = LocalManifestStore::UnusedDeviceName(base);
    return MoveEntry(root, LocalManifestStore::DevicePath(name), error) ? OperationResult::kDone
                                                                        : OperationResult::kFailed;
}

}

void DeviceImport::Start(const QUrl& archive) {
    const QString source = emu_.Get<FileAccess>().LocalPath(archive);
    if (source.isEmpty()) return;
    const QString label = PathDisplayName(source);
    const QString safe  = SafeBundleNameFrom(QFileInfo(label).completeBaseName());
    const QString base  = safe.isEmpty() ? QString::fromLatin1(kFallbackName) : safe;
    auto          name  = std::make_shared<QString>();
    emu_.Get<ManagerOperations>().Run(
        QStringLiteral("Importing %1…").arg(label),
        [source, label, base, name](const OperationProgress& progress, QString& error) {
            return ImportArchive(source, label, base, *name, progress, error);
        },
        QStringLiteral("Imported %1").arg(label), [this, name](OperationResult result) {
            if (result == OperationResult::kDone) emit imported(*name, MissingRepository(*name));
        });
}

QString DeviceImport::MissingRepository(const QString& name) const {
    const std::optional<RepositoryLink> link = DeviceDirectory(LocalManifestStore::DevicePath(name)).ReadLink();
    if (!link) return QString();
    for (const BundleRepository& repository : emu_.Get<BundleRepositories>().Read())
        if (repository.url == link->repository_url) return QString();
    return link->repository_url;
}
