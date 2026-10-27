#include "device_inventory.h"

#include "bundle_catalog.h"
#include "bundle_name.h"
#include "device_directory.h"
#include "local_manifest_store.h"
#include "text_compare.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/platform/host_file.h>

#include <QDir>
#include <QFileInfo>
#include <QHash>

#include <algorithm>

REGISTER_SERVICE(DeviceInventory);

namespace {

bool PackageArtifactPresent(const QString& device_path, const RemotePackage& package) {
    const QString path = QDir(device_path).filePath(package.key);
    if (package.is_directory)
        return QFileInfo(path).isDir() && !QDir(path).entryList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden |
                                                                QDir::System).isEmpty();
    return QFileInfo(path).isFile();
}

std::vector<PackageStatus> PackageStatuses(const RemoteBundle& remote, const LocalBundleRecord* record,
                                           const QString* device_path) {
    std::vector<PackageStatus> statuses;
    for (const RemotePackage& package : remote.packages) {
        PackageStatus status;
        status.remote    = package;
        status.installed = device_path != nullptr && PackageArtifactPresent(*device_path, package);
        const LocalPackageRecord* local = record ? record->FindPackage(package.category, package.key) : nullptr;
        if (local && status.installed) status.installed_sha256 = local->sha256;
        statuses.push_back(std::move(status));
    }
    return statuses;
}

void FillMetaGaps(DeviceBundle& device, const ParsedCerfJson& remote) {
    DeviceMeta&       meta  = device.meta;
    const DeviceMeta& other = remote.meta;
    if (meta.device_name.isEmpty()) meta.device_name = other.device_name;
    if (meta.board_id.isEmpty()) meta.board_id = other.board_id;
    if (meta.os_name.isEmpty()) meta.os_name = other.os_name;
    if (meta.os_ver_major == 0) meta.os_ver_major = other.os_ver_major;
    if (meta.os_ver_minor == 0) meta.os_ver_minor = other.os_ver_minor;
    if (meta.os_ver_build == 0) meta.os_ver_build = other.os_ver_build;
    if (meta.os_language.isEmpty()) meta.os_language = other.os_language;
    if (meta.os_year == 0) meta.os_year = other.os_year;
    if (meta.os_notes.isEmpty()) meta.os_notes = other.os_notes;
    if (!meta.forbid_guest_additions) meta.forbid_guest_additions = other.forbid_guest_additions;
    if (!meta.source) meta.source = other.source;
    if (!device.default_screen_width) device.default_screen_width = remote.width;
    if (!device.default_screen_height) device.default_screen_height = remote.height;
}

bool CerfJsonDiffers(const QString& path, const Json& remote) {
    QString                   error;
    const std::optional<Json> local = ReadJsonObject(path, error);
    if (!local) return true;
    return nlohmann::json::parse(local->dump()) != nlohmann::json::parse(remote.dump());
}

std::optional<qint64> RomSize(const DeviceDirectory& directory) {
    uint64_t size = 0;
    if (!cerfcore::host_platform::HostRegularFileSize(directory.ResolveFile(directory.RomPrimary()).toStdString(),
                                                      size))
        return std::nullopt;
    return qint64(size);
}

QStringList LocalDeviceDirs() {
    QStringList names;
    for (const QFileInfo& entry : QDir(LocalManifestStore::DevicesDir())
                                      .entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot | QDir::Hidden)) {
        const QString name = entry.fileName();
        if (IsSafeBundleName(name)) names.append(name);
    }
    return names;
}

QString RemoteKey(const RemoteBundle& remote) { return remote.repo_url + QStringLiteral("::") + remote.name; }

}

const RemoteBundle* DeviceInventory::LinkedRemote(const QString& device_path) const {
    const std::optional<RepositoryLink> link = DeviceDirectory(device_path).ReadLink();
    if (!link) return nullptr;
    return emu_.Get<BundleCatalog>().Find(link->repository_url, link->name_on_repository);
}

std::vector<DeviceBundle> DeviceInventory::List() const {
    const LocalManifest  installed = emu_.Get<LocalManifestStore>().Snapshot();
    const BundleCatalog& catalog   = emu_.Get<BundleCatalog>();
    std::vector<DeviceBundle>          devices;
    std::vector<std::pair<QString, QString>> claimed;

    for (const QString& name : LocalDeviceDirs()) {
        const QString           path = LocalManifestStore::DevicePath(name);
        const DeviceDirectory   directory(path);
        const ParsedCerfJson    parsed = directory.ReadMeta();
        const auto              record = installed.constFind(name);
        DeviceBundle            device;
        device.name                  = name;
        device.key                   = name;
        device.local_dir_exists      = true;
        device.meta                  = parsed.meta;
        device.default_screen_width  = parsed.width;
        device.default_screen_height = parsed.height;
        device.rom_size              = RomSize(directory);
        if (record != installed.constEnd()) device.installed_sha256 = record->sha256;
        if (const RemoteBundle* remote = LinkedRemote(path)) {
            claimed.emplace_back(remote->repo_url, remote->name);
            device.remote   = *remote;
            device.packages = PackageStatuses(*remote, record != installed.constEnd() ? &*record : nullptr, &path);
            FillMetaGaps(device, remote->cerf_json ? ParseCerfJson(*remote->cerf_json) : ParsedCerfJson{});
            if (!device.HasUpdate() && remote->cerf_json &&
                CerfJsonDiffers(directory.FilePath(DeviceDirectory::BaseConfigName()), *remote->cerf_json))
                device.cerf_json_pending = true;
        }
        devices.push_back(std::move(device));
    }

    QHash<QString, size_t> remote_slots;
    for (const RemoteBundle& remote : catalog.Bundles()) {
        if (std::find(claimed.begin(), claimed.end(), std::make_pair(remote.repo_url, remote.name)) != claimed.end())
            continue;
        const ParsedCerfJson parsed = remote.cerf_json ? ParseCerfJson(*remote.cerf_json) : ParsedCerfJson{};
        DeviceBundle         device;
        device.name                  = remote.name;
        device.key                   = RemoteKey(remote);
        device.remote                = remote;
        device.meta                  = parsed.meta;
        device.default_screen_width  = parsed.width;
        device.default_screen_height = parsed.height;
        device.packages              = PackageStatuses(remote, nullptr, nullptr);
        const auto slot = remote_slots.constFind(device.key);
        if (slot != remote_slots.constEnd()) {
            devices[*slot] = std::move(device);
            continue;
        }
        remote_slots.insert(device.key, devices.size());
        devices.push_back(std::move(device));
    }

    std::stable_sort(devices.begin(), devices.end(), [](const DeviceBundle& a, const DeviceBundle& b) {
        return SortTextLess(a.name, b.name);
    });
    return devices;
}

std::optional<DeviceBundle> DeviceInventory::Find(const QString& key) const {
    for (DeviceBundle& device : List())
        if (device.key == key) return std::move(device);
    return std::nullopt;
}

std::optional<DeviceBundle> DeviceInventory::FindByRemote(const QString& remote_key) const {
    for (DeviceBundle& device : List())
        if (device.remote && RemoteKey(*device.remote) == remote_key) return std::move(device);
    return std::nullopt;
}

std::optional<PackageStatus> DeviceInventory::FindPackage(const QString& name, const QString& category,
                                                          const QString& key) const {
    const std::optional<DeviceBundle> device = Find(name);
    if (!device) return std::nullopt;
    const PackageStatus* status = device->FindPackage(category, key);
    if (status == nullptr) return std::nullopt;
    return *status;
}

void DeviceInventory::BackfillInstalledSha256() const {
    QString error;
    const bool saved = emu_.Get<LocalManifestStore>().Update(
        [this](LocalManifest& installed) {
            bool changed = false;
            for (const QString& name : LocalDeviceDirs()) {
                auto record = installed.find(name);
                if (record == installed.end() || record->sha256) continue;
                const RemoteBundle* remote = LinkedRemote(LocalManifestStore::DevicePath(name));
                if (remote == nullptr || !remote->archive_sha256) continue;
                record->sha256 = remote->archive_sha256;
                changed        = true;
            }
            return changed;
        },
        error);
    if (!saved) LOG(Manager, "%s\n", qUtf8Printable(error));
}
