#include "shader_import.h"

#include "device_file_value.h"
#include "file_access.h"
#include "filesystem_path.h"
#include "host_file_copy.h"
#include "manager_operations.h"
#include "path_containment.h"
#include "shader_catalog.h"
#include "zip_extract.h"

#include "../CerfStyle/touch_frontend.h"
#include "../shader_selection.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QDir>
#include <QFileInfo>
#include <QTemporaryDir>

#include <filesystem>
#include <optional>
#include <system_error>

REGISTER_SERVICE(ShaderImport);

namespace {

namespace fs = std::filesystem;

constexpr char kArchiveCopyName[] = "import.zip";

QString CleanPath(const QString& path) { return QDir::cleanPath(QFileInfo(QDir::fromNativeSeparators(path)).absoluteFilePath()); }

QString ShadersRoot() { return CleanPath(QString::fromStdString(cerffrontend::ShaderSelection::Directory())); }

OperationResult Finish(bool done, bool existed, const QString& name, const QString& target, QString& error) {
    if (done && ShaderCatalog::PresetPaths(target).isEmpty()) {
        error = QStringLiteral("%1 holds no .slangp preset.").arg(name);
        done  = false;
    }
    if (done) return OperationResult::kDone;
    QString cleanup;
    if (!existed && !RemoveEntry(PathOf(target), cleanup)) error += QLatin1Char('\n') + cleanup;
    return OperationResult::kFailed;
}

OperationResult ExtractArchive(const QString& source, const QString& name, const QString& target,
                               const OperationProgress& progress, QString& error) {
    QTemporaryDir staging;
    QString       archive = source;
    if (IsDocumentFileValue(source)) {
        if (!staging.isValid()) {
            error = QStringLiteral("cannot create a temporary folder (%1)").arg(staging.errorString());
            return OperationResult::kFailed;
        }
        archive                       = staging.filePath(QString::fromLatin1(kArchiveCopyName));
        const OperationResult copied = CopyHostFile(source, archive, progress, error);
        if (copied != OperationResult::kDone) return copied;
    }
    progress.Report(QStringLiteral("Extracting %1…").arg(name), 0, std::nullopt);
    const bool existed = EntryExists(PathOf(target));
    return Finish(SafeExtract(archive, target, error), existed, name, target, error);
}

OperationResult CopyFolder(const QString& source, const QString& name, const QString& target, QString& error) {
    const QString root = ShadersRoot();
    if (PathInside(root, source) || PathInside(source, root)) {
        error = QStringLiteral("%1 is inside the shaders folder, or holds it.").arg(QDir::toNativeSeparators(source));
        return OperationResult::kFailed;
    }
    const bool      existed = EntryExists(PathOf(target));
    std::error_code ec;
    fs::copy(PathOf(source), PathOf(target), fs::copy_options::recursive | fs::copy_options::overwrite_existing, ec);
    if (ec) error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(target), ErrorCodeText(ec));
    return Finish(!ec, existed, name, target, error);
}

}

bool ShaderImport::FolderImport() const { return !TouchFrontend::Active(); }

void ShaderImport::ImportArchive(const QUrl& url) {
    const QString source = emu_.Get<FileAccess>().LocalPath(url);
    if (source.isEmpty()) return;
    const QString name   = PathDisplayName(source);
    const QString target = ShadersRoot() + QLatin1Char('/') + QFileInfo(name).completeBaseName();
    emu_.Get<ManagerOperations>().Run(
        QStringLiteral("Importing %1…").arg(name),
        [source, name, target](const OperationProgress& progress, QString& error) {
            if (!MakeDirectory(ShadersRoot(), error)) return OperationResult::kFailed;
            return ExtractArchive(source, name, target, progress, error);
        },
        QStringLiteral("Imported %1").arg(name), [this](OperationResult result) {
            if (result == OperationResult::kDone) emu_.Get<ShaderCatalog>().Changed();
        });
}

void ShaderImport::ImportFolder(const QUrl& url) {
    const QString picked = emu_.Get<FileAccess>().LocalPath(url);
    if (picked.isEmpty()) return;
    const QString source = CleanPath(picked);
    const QString name   = QFileInfo(source).fileName();
    const QString target = ShadersRoot() + QLatin1Char('/') + name;
    emu_.Get<ManagerOperations>().Run(
        QStringLiteral("Importing %1…").arg(name),
        [source, name, target](const OperationProgress&, QString& error) {
            if (!MakeDirectory(ShadersRoot(), error)) return OperationResult::kFailed;
            return CopyFolder(source, name, target, error);
        },
        QStringLiteral("Imported %1").arg(name), [this](OperationResult result) {
            if (result == OperationResult::kDone) emu_.Get<ShaderCatalog>().Changed();
        });
}
