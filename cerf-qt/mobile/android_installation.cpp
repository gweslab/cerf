#include "android_installation.h"

#include "../cerfman/file_writer.h"
#include "../cerfman/filesystem_path.h"
#include "../cerfman/global_config_migration.h"
#include "../cerfman/install_directories.h"
#include "../cerfman/json_file.h"
#include "../cerfman/path_containment.h"

#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/log.h>
#include <cerfcore/platform/host_app_data_directory.h>
#include "../install_root_files.h"
#include "../qt_resource_paths.h"

#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QJniObject>
#include <QResource>
#include <QSet>
#include <QStandardPaths>
#include <QString>
#include <QStringList>
#include <QtCore/qcoreapplication_platform.h>

#include <optional>

namespace {

constexpr char kRecordName[]    = "installed_files.json";
constexpr char kUpdateTimeKey[] = "package_update_time";
constexpr char kFilesKey[]      = "files";

qint64 PackageUpdateTime() {
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    const QJniObject manager = context.callObjectMethod("getPackageManager", "()Landroid/content/pm/PackageManager;");
    const QJniObject name    = context.callObjectMethod("getPackageName", "()Ljava/lang/String;");
    const QJniObject info    = manager.callObjectMethod(
        "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;", name.object<jstring>(), jint(0));
    return qint64(info.getField<jlong>("lastUpdateTime"));
}

bool Place(const QString& source, const QString& target, QString& error) {
    if (!MakeDirectory(QFileInfo(target).absolutePath(), error)) return false;
    FileWriter out(target);
    return out.Open(error) && out.Write(QResource(source).uncompressedData(), error) && out.Close(error);
}

QStringList RecordedFiles(const Json& record) {
    QStringList files;
    for (const Json& entry : record.value(kFilesKey, Json::array()))
        files.append(JsonString(entry));
    return files;
}

bool PlaceBundledFiles(const QString& root, QStringList& placed) {
    const QDir   resources(InstallResourceRoot());
    QDirIterator it(resources.path(), QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString source   = it.next();
        const QString relative = resources.relativeFilePath(source);
        const QString target   = root + QLatin1Char('/') + relative;
        QString error;
        if (relative == QLatin1String(cerffrontend::kGlobalConfigFileName)) {
            const QByteArray staged = QResource(source).uncompressedData();
            if (!MigrateGlobalConfig(Json::parse(staged.cbegin(), staged.cend()), target, error)) {
                LOG(Caution, "cannot migrate the global configuration (%s)\n", qUtf8Printable(error));
                return false;
            }
            continue;
        }
        if (!Place(source, target, error)) {
            LOG(Caution, "%s\n", qUtf8Printable(error));
            return false;
        }
        placed.append(relative);
    }
    return true;
}

bool RemoveDroppedFiles(const QString& root, const QStringList& before, const QStringList& now) {
    const QSet<QString> kept(now.cbegin(), now.cend());
    for (const QString& relative : before) {
        if (kept.contains(relative)) continue;
        const QString path = root + QLatin1Char('/') + relative;
        QString       error;
        if (!RemoveEntry(PathOf(path), error)) {
            LOG(Caution, "%s\n", qUtf8Printable(error));
            return false;
        }
        for (QString dir = QFileInfo(path).absolutePath(); PathBelow(root, dir) && QDir().rmdir(dir);)
            dir = QFileInfo(dir).absolutePath();
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
    const QString       record_path = root + QLatin1Char('/') + QLatin1String(kRecordName);
    std::optional<Json> record      = ReadJsonObjectIfPresent(record_path, error);
    if (!record) {
        LOG(Manager, "%s Every bundled file is placed again.\n", qUtf8Printable(error));
        record = Json::object();
    }
    if (record->contains(kUpdateTimeKey) && record->at(kUpdateTimeKey).get<qint64>() == update_time) return true;

    QStringList placed;
    if (!PlaceBundledFiles(root, placed) || !RemoveDroppedFiles(root, RecordedFiles(*record), placed)) return false;

    Json files = Json::array();
    for (const QString& relative : placed) files.push_back(relative.toStdString());
    if (!WriteJsonFile(record_path, Json{{kUpdateTimeKey, update_time}, {kFilesKey, files}}, error)) {
        LOG(Caution, "%s\n", qUtf8Printable(error));
        return false;
    }
    return true;
}
