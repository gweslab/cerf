#include "device_bundle.h"

#include "package_identity.h"
#include "sha256_text.h"

namespace {

bool ShaDiffers(const std::optional<QString>& installed, const std::optional<QString>& remote) {
    return installed && remote && !SameSha256(*installed, *remote);
}

}

bool PackageStatus::HasUpdate() const { return installed && ShaDiffers(installed_sha256, remote.archive_sha256); }

bool DeviceBundle::HasUpdate() const {
    return local_dir_exists && remote && ShaDiffers(installed_sha256, remote->archive_sha256);
}

bool DeviceBundle::HasPackageUpdates() const {
    for (const PackageStatus& package : packages)
        if (package.HasUpdate()) return true;
    return false;
}

bool DeviceBundle::Updatable() const { return HasUpdate() || cerf_json_pending; }

bool DeviceBundle::HasAnyUpdate() const { return Updatable() || HasPackageUpdates(); }

QString DeviceBundle::DeviceName() const { return meta.DeviceNameOr(name); }

QString DeviceBundle::StateLabel() const {
    if (IsUserDevice()) return QStringLiteral("User device");
    if (HasUpdate()) return QStringLiteral("Update available");
    if (cerf_json_pending) return QStringLiteral("Device pending update");
    if (IsInstalled()) return QStringLiteral("Installed");
    return QStringLiteral("Available");
}

const PackageStatus* DeviceBundle::FindPackage(const QString& category, const QString& package_key) const {
    for (const PackageStatus& status : packages)
        if (IsPackage(status.remote, category, package_key)) return &status;
    return nullptr;
}
