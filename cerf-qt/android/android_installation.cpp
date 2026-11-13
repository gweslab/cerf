#include "android_installation.h"

#include "../cerfman/file_writer.h"
#include "../cerfman/filesystem_path.h"
#include "../cerfman/global_config_migration.h"
#include "../cerfman/install_directories.h"
#include "../cerfman/installed_files.h"
#include "../cerfman/json_file.h"

#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/log.h>
#include <cerfcore/platform/host_app_data_directory.h>
#include "../android_package.h"
#include "../install_root_files.h"
#include "../qt_resource_paths.h"

#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QJniObject>
#include <QResource>
#include <QStandardPaths>
#include <QString>
#include <QStringList>

#include <optional>

namespace {

constexpr char kUpdateTimeKey[] = "package_update_time";

qint64 PackageUpdateTime() {
    const QJniObject manager = AndroidPackageManager();
    const QJniObject name    = AndroidPackageName();
    const QJniObject info    = manager.callObjectMethod(
        "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;", name.object<jstring>(), jint(0));
    return qint64(info.getField<jlong>("lastUpdateTime"));
}

bool Place(const QString& source, const QString& target, QString& error) {
    if (!MakeDirectory(QFileInfo(target).absolutePath(), error)) return false;
    FileWriter out(target);
    return out.Open(error) && out.Write(QResource(source).uncompressedData(), error) && out.Close(error);
}

QStringList BundledFiles(const QDir& resources) {
    QStringList  files;
    QDirIterator it(resources.path(), QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString relative = resources.relativeFilePath(it.next());
        if (relative != QLatin1String(cerffrontend::kGlobalConfigFileName)) files.append(relative);
    }
    return files;
}

bool PlaceBundledFiles(const QString& root, const QDir& resources, const QStringList& files) {
    QString          error;
    const QByteArray staged = QResource(resources.filePath(QLatin1String(cerffrontend::kGlobalConfigFileName)))
                                  .uncompressedData();
    if (!MigrateGlobalConfig(Json::parse(staged.cbegin(), staged.cend()),
                             root + QLatin1Char('/') + QLatin1String(cerffrontend::kGlobalConfigFileName), error)) {
        LOG(Caution, "cannot migrate the global configuration (%s)\n", qUtf8Printable(error));
        return false;
    }
    for (const QString& relative : files) {
        if (!AdoptInstalledName(PathOf(root), PathOf(relative), error) ||
            !Place(resources.filePath(relative), root + QLatin1Char('/') + relative, error)) {
            LOG(Caution, "%s\n", qUtf8Printable(error));
            return false;
        }
    }
    return true;
}

bool RemoveDroppedFiles(const QString& root, const Json& record, const QStringList& bundled) {
    const std::filesystem::path base = PathOf(root);
    for (const QString& relative : DroppedFiles(InstalledFileList(record).value_or(QStringList()), bundled)) {
        const std::optional<std::filesystem::path> entry = InstalledFileEntry(relative);
        if (!entry) {
            LOG(Manager, "%s is not a path inside the installation; it is kept\n", qUtf8Printable(relative));
            continue;
        }
        QString error;
        if (RemoveInstalledFile(base, *entry, error) == InstalledFileRemoval::kFailed) {
            LOG(Caution, "%s\n", qUtf8Printable(error));
            return false;
        }
    }
    return true;
}

}

std::string cerfcore::host::AppDataDirectory() {
    const QString root = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    return root.isEmpty() ? std::string() : QDir::toNativeSeparators(root + QLatin1Char('/')).toStdString();
}

bool ProvisionInstallation() {
    const QString root = InstallRoot();
    QString       error;
    if (root.isEmpty() || !MakeDirectory(QString::fromStdString(cerfcore::DevicesDir()), error)) {
        LOG(Caution, "no writable application data folder (%s): %s\n", qUtf8Printable(root), qUtf8Printable(error));
        return false;
    }
    const qint64        update_time = PackageUpdateTime();
    const QString       record_path = root + QLatin1Char('/') + QLatin1String(cerffrontend::kInstalledFilesName);
    std::optional<Json> record      = ReadJsonObjectIfPresent(record_path, error);
    if (!record) {
        LOG(Manager, "%s Every bundled file is placed again.\n", qUtf8Printable(error));
        record = Json::object();
    }
    if (record->contains(kUpdateTimeKey) && record->at(kUpdateTimeKey).get<qint64>() == update_time) return true;

    const QDir        resources(InstallResourceRoot());
    const QStringList bundled = BundledFiles(resources);
    if (!RemoveDroppedFiles(root, *record, bundled) || !PlaceBundledFiles(root, resources, bundled)) return false;

    Json installed            = InstalledFileRecord(bundled);
    installed[kUpdateTimeKey] = update_time;
    if (!WriteJsonFile(record_path, installed, error)) {
        LOG(Caution, "%s\n", qUtf8Printable(error));
        return false;
    }
    return true;
}
