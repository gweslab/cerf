#include "bundle_installer.h"

#include "device_directory.h"
#include "device_form_rules.h"
#include "filesystem_path.h"
#include "http_client.h"
#include "http_download.h"
#include "local_manifest_store.h"
#include "path_containment.h"
#include "zip_extract.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QDir>
#include <QFileInfo>
#include <QRandomGenerator>
#include <QTemporaryDir>

#include <filesystem>
#include <system_error>
#include <utility>
#include <vector>

REGISTER_SERVICE(BundleInstaller);

namespace fs = std::filesystem;

namespace {

QString PreviousPath(const QTemporaryDir& temp) { return QDir(temp.path()).filePath(QStringLiteral("previous")); }

bool MovePath(const QString& from, const QString& to, QString& error) {
    std::error_code ec;
    fs::rename(PathOf(from), PathOf(to), ec);
    if (!ec) return true;
    error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(from), ErrorCodeText(ec));
    return false;
}

bool ListsEntry(const QString& dir, const QStringList& entries, const QString& entry) {
    for (const QString& listed : entries) {
        std::error_code ec;
        if (fs::equivalent(PathOf(QDir(dir).filePath(listed)), PathOf(QDir(dir).filePath(entry)), ec)) return true;
    }
    return false;
}

class MoveLog {
public:
    bool Run(const QString& from, const QString& to, QString& error) {
        if (!MovePath(from, to, error)) return false;
        done_.push_back({from, to});
        return true;
    }

    bool Undo(QString& error) {
        while (!done_.empty()) {
            if (!MovePath(done_.back().second, done_.back().first, error)) return false;
            done_.pop_back();
        }
        return true;
    }

private:
    std::vector<std::pair<QString, QString>> done_;
};

OperationResult KeepForRecovery(QTemporaryDir& temp, const QString& failure, QString& error) {
    temp.setAutoRemove(false);
    error += QStringLiteral("\nThe previous files could not be put back: %1\nThey are in %2")
                 .arg(failure, QDir::toNativeSeparators(temp.path()));
    return OperationResult::kFailed;
}

}

QString BundleInstaller::AllocateDirName(const QString& base) const {
    if (!EntryExists(PathOf(LocalManifestStore::DevicePath(base)))) return base;
    static constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (;;) {
        QString suffix;
        for (int i = 0; i < 8; ++i)
            suffix.append(QLatin1Char(kAlphabet[QRandomGenerator::global()->bounded(int(sizeof(kAlphabet) - 1))]));
        const QString candidate = base + QLatin1Char('_') + suffix;
        if (!EntryExists(PathOf(LocalManifestStore::DevicePath(candidate)))) return candidate;
    }
}

OperationResult BundleInstaller::DownloadExtract(const QString& url, const QString& label, const QString& temp_dir,
                                                 std::optional<qint64> size, std::optional<QString> sha256,
                                                 const OperationProgress& progress, QString& prepared,
                                                 QString& error) {
    const QString archive = QDir(temp_dir).filePath(QStringLiteral("archive.zip"));
    const QString extract = QDir(temp_dir).filePath(QStringLiteral("extract"));
    if (!MakeDirectory(extract, error)) return OperationResult::kFailed;
    const DownloadRequest request{url, archive, label, size, sha256, emu_.Get<HttpClient>().UserAgent()};
    const OperationResult result = DownloadVerified(request, progress, error);
    if (result != OperationResult::kDone) return result;
    progress.Report(QStringLiteral("Extracting %1…").arg(label), 0, std::nullopt);
    if (!SafeExtract(archive, extract, error)) return OperationResult::kFailed;
    prepared = PreparedBundleRoot(extract);
    return OperationResult::kDone;
}

bool BundleInstaller::KeptStorageEntries(const QString& name, const QString& target, const QString& prepared,
                                         QStringList& kept, QString& error) const {
    if (!QFileInfo(target).isDir()) return true;
    const QString root = QDir::cleanPath(QDir(target).absolutePath());
    for (const QString& path : emu_.Get<DeviceFormRules>().StorageFiles(target)) {
        const QString absolute = QDir::cleanPath(QDir(target).absoluteFilePath(path));
        if (!PathBelow(root, absolute)) continue;
        const QString first = absolute.mid(root.size() + 1).section(QLatin1Char('/'), 0, 0);
        if (!first.isEmpty() && EntryExists(PathOf(QDir(target).filePath(first))) && !ListsEntry(target, kept, first))
            kept.append(first);
    }
    for (const QString& entry : kept) {
        if (EntryExists(PathOf(QDir(prepared).filePath(entry)))) {
            error = QStringLiteral("%1: the bundle carries %2, which holds the device's storage").arg(name, entry);
            return false;
        }
    }
    return true;
}

bool BundleInstaller::WriteBundleConfig(const QString& target, const RemoteBundle& bundle, QString& error) const {
    if (bundle.cerf_json &&
        !WriteJsonFile(QDir(target).filePath(DeviceDirectory::BaseConfigName()), *bundle.cerf_json, error))
        return false;
    return DeviceDirectory(target).WriteLink(RepositoryLink{bundle.repo_url, bundle.name}, error);
}

OperationResult BundleInstaller::RunInstall(const RemoteBundle& bundle, std::optional<QString> dir_name,
                                            const OperationProgress& progress, QString& error) {
    const QString                name   = dir_name ? *dir_name : AllocateDirName(bundle.name);
    const std::optional<QString> target = LocalManifestStore::SafeDevicePath(name, error);
    if (!target) return OperationResult::kFailed;

    QTemporaryDir temp(QDir(LocalManifestStore::DevicesDir()).filePath(QStringLiteral(".sync_XXXXXX")));
    if (!temp.isValid()) {
        error = temp.errorString();
        return OperationResult::kFailed;
    }
    QString               prepared;
    const OperationResult downloaded = DownloadExtract(bundle.ArchiveUrl(), name, temp.path(), bundle.archive_size,
                                                       bundle.archive_sha256, progress, prepared, error);
    if (downloaded != OperationResult::kDone) return downloaded;

    QStringList kept;
    if (!KeptStorageEntries(name, *target, prepared, kept, error)) return OperationResult::kFailed;

    std::vector<LocalPackageRecord> preserved;
    MoveLog                         carried;
    const QString                   previous  = PreviousPath(temp);
    const bool                      replacing = EntryExists(PathOf(*target));
    auto                            fail_back = [&](bool target_moved) {
        QString failure;
        if ((!target_moved || MovePath(previous, *target, failure)) && carried.Undo(failure))
            return OperationResult::kFailed;
        return KeepForRecovery(temp, failure, error);
    };
    auto carry = [&](const QString& entry) {
        const QString destination = QDir(prepared).filePath(entry);
        return RemoveEntry(PathOf(destination), error) &&
               carried.Run(QDir(*target).filePath(entry), destination, error);
    };

    if (replacing) {
        QStringList         entries   = kept;
        const LocalManifest installed = emu_.Get<LocalManifestStore>().Snapshot();
        const auto          record    = installed.constFind(name);
        if (record != installed.constEnd()) {
            for (const LocalPackageRecord& package : record->packages) {
                if (!EntryExists(PathOf(QDir(*target).filePath(package.key)))) continue;
                preserved.push_back(package);
                if (!ListsEntry(*target, entries, package.key)) entries.append(package.key);
            }
        }
        for (const QString& entry : entries)
            if (!carry(entry)) return fail_back(false);
        const QString user_config = QDir(*target).filePath(DeviceDirectory::UserConfigName());
        const QString user_copy   = QDir(prepared).filePath(DeviceDirectory::UserConfigName());
        if (QFileInfo(user_config).isFile() &&
            (!RemoveEntry(PathOf(user_copy), error) || !CopyFileTo(PathOf(user_config), PathOf(user_copy), error)))
            return fail_back(false);
    }
    if (!WriteBundleConfig(prepared, bundle, error)) return fail_back(false);
    if (replacing && !MovePath(*target, previous, error)) return fail_back(false);
    if (!MovePath(prepared, *target, error)) return fail_back(replacing);

    const bool saved = emu_.Get<LocalManifestStore>().Update(
        [&](LocalManifest& manifest) {
            LocalBundleRecord fresh;
            fresh.updated_at = bundle.updated_at;
            fresh.sha256     = bundle.archive_sha256;
            fresh.packages   = preserved;
            manifest.insert(name, std::move(fresh));
            return true;
        },
        error);
    if (saved) return OperationResult::kDone;
    QString failure;
    if (!MovePath(*target, prepared, failure)) return KeepForRecovery(temp, failure, error);
    return fail_back(replacing);
}

ManagerOperations::Job BundleInstaller::Install(const RemoteBundle& bundle, std::optional<QString> dir_name) {
    return [this, bundle, dir_name](const OperationProgress& progress, QString& error) {
        return RunInstall(bundle, dir_name, progress, error);
    };
}

bool BundleInstaller::RecordPackage(const QString& name, const RemotePackage& package, QString& error) {
    return emu_.Get<LocalManifestStore>().Update(
        [&](LocalManifest& manifest) {
            LocalBundleRecord& record = manifest[name];
            record.DropPackage(package.category, package.key);
            record.packages.push_back({package.category, package.key, package.is_directory, package.archive_sha256});
            return true;
        },
        error);
}

QString BundleInstaller::PackageTargetProblem(const QString& name) {
    if (QFileInfo(LocalManifestStore::DevicePath(name)).isDir()) return QString();
    return QStringLiteral("%1 is not installed; install the device first.").arg(name);
}

OperationResult BundleInstaller::RunInstallPackage(const QString& name, const RemotePackage& package,
                                                   const OperationProgress& progress, QString& error) {
    const std::optional<QString> target = LocalManifestStore::SafeDevicePath(name, error);
    if (!target) return OperationResult::kFailed;
    error = PackageTargetProblem(name);
    if (!error.isEmpty()) return OperationResult::kFailed;
    const QString label = QStringLiteral("%1: %2").arg(name, package.name);
    QTemporaryDir temp(QDir(LocalManifestStore::DevicesDir()).filePath(QStringLiteral(".pkg_XXXXXX")));
    if (!temp.isValid()) {
        error = temp.errorString();
        return OperationResult::kFailed;
    }
    QString               prepared;
    const OperationResult downloaded = DownloadExtract(package.ArchiveUrl(), label, temp.path(), package.archive_size,
                                                       package.archive_sha256, progress, prepared, error);
    if (downloaded != OperationResult::kDone) return downloaded;
    const QString destination = QDir(*target).filePath(package.key);
    QString       source      = prepared;
    if (!package.is_directory) {
        source = QDir(prepared).filePath(package.key);
        if (!QFileInfo(source).isFile()) {
            error = QStringLiteral("%1: archive does not contain %2").arg(label, package.key);
            return OperationResult::kFailed;
        }
    }
    const QString previous  = PreviousPath(temp);
    const bool    replacing = EntryExists(PathOf(destination));
    if (replacing && !MovePath(destination, previous, error)) return OperationResult::kFailed;
    QString failure;
    if (!MovePath(source, destination, error)) {
        if (replacing && !MovePath(previous, destination, failure)) return KeepForRecovery(temp, failure, error);
        return OperationResult::kFailed;
    }
    if (RecordPackage(name, package, error)) return OperationResult::kDone;
    if (!MovePath(destination, source, failure) || (replacing && !MovePath(previous, destination, failure)))
        return KeepForRecovery(temp, failure, error);
    return OperationResult::kFailed;
}

ManagerOperations::Job BundleInstaller::InstallPackage(const QString& name, const RemotePackage& package) {
    return [this, name, package](const OperationProgress& progress, QString& error) {
        return RunInstallPackage(name, package, progress, error);
    };
}

ManagerOperations::Job BundleInstaller::RefreshCerfJson(const QString& name, const Json& cerf_json) {
    return [name, cerf_json](const OperationProgress&, QString& error) {
        const std::optional<QString> target = LocalManifestStore::SafeDevicePath(name, error);
        if (!target) return OperationResult::kFailed;
        return WriteJsonFile(QDir(*target).filePath(DeviceDirectory::BaseConfigName()), cerf_json, error)
                   ? OperationResult::kDone
                   : OperationResult::kFailed;
    };
}

ManagerOperations::Job BundleInstaller::Delete(const QString& name) {
    return [this, name](const OperationProgress&, QString& error) {
        const std::optional<QString> target = LocalManifestStore::SafeDevicePath(name, error);
        if (!target || !RemoveEntry(PathOf(*target), error)) return OperationResult::kFailed;
        const bool saved = emu_.Get<LocalManifestStore>().Update(
            [&](LocalManifest& manifest) {
                manifest.remove(name);
                return true;
            },
            error);
        return saved ? OperationResult::kDone : OperationResult::kFailed;
    };
}

ManagerOperations::Job BundleInstaller::DeletePackage(const QString& name, const QString& category, const QString& key) {
    return [this, name, category, key](const OperationProgress&, QString& error) {
        const std::optional<QString> target = LocalManifestStore::SafeDevicePath(name, error);
        if (!target || !RemoveEntry(PathOf(QDir(*target).filePath(key)), error)) return OperationResult::kFailed;
        const bool saved = emu_.Get<LocalManifestStore>().Update(
            [&](LocalManifest& manifest) {
                auto record = manifest.find(name);
                if (record == manifest.end()) return false;
                record->DropPackage(category, key);
                return true;
            },
            error);
        return saved ? OperationResult::kDone : OperationResult::kFailed;
    };
}
