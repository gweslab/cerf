#include "local_manifest_store.h"

#include "bundle_name.h"
#include "path_containment.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/log.h>

#include <QDir>
#include <QFileInfo>

REGISTER_SERVICE(LocalManifestStore);

QString LocalManifestStore::DevicesDir() {
    return QDir::cleanPath(QString::fromStdString(cerfcore::DevicesDir()));
}

QString LocalManifestStore::DevicePath(const QString& name) { return QDir(DevicesDir()).filePath(name); }

QString LocalManifestStore::RelativeDevicePath(const QString& name) {
    return QStringLiteral("%1/%2").arg(QString::fromUtf8(cerfcore::kDevicesDirName), name);
}

std::optional<QString> LocalManifestStore::SafeDevicePath(const QString& name, QString& error) {
    if (!IsSafeBundleName(name)) {
        error = QStringLiteral("unsafe bundle name: '%1'").arg(name);
        return std::nullopt;
    }
    const QString devices = QDir::cleanPath(QDir(DevicesDir()).absolutePath());
    const QString path    = QDir::cleanPath(QDir(devices).absoluteFilePath(name));
    if (!PathBelow(devices, path)) {
        error = QStringLiteral("refusing to operate outside %1").arg(QDir::toNativeSeparators(devices));
        return std::nullopt;
    }
    const QFileInfo info(path);
    if (info.isSymbolicLink() || info.isJunction()) {
        error = QStringLiteral("refusing to operate on a link: %1").arg(QDir::toNativeSeparators(path));
        return std::nullopt;
    }
    return path;
}

QString LocalManifestStore::Path() const { return QDir(DevicesDir()).filePath(QStringLiteral("manifest.json")); }

void LocalManifestStore::Reload() {
    LocalManifest loaded;
    QString       error;
    if (!LoadLocalManifest(Path(), loaded, error)) {
        LOG(Manager, "%s\n", qUtf8Printable(error));
        loaded.clear();
    }
    std::lock_guard<std::mutex> lock(mutex_);
    manifest_ = std::move(loaded);
}

LocalManifest LocalManifestStore::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return manifest_;
}

bool LocalManifestStore::Update(const std::function<bool(LocalManifest& manifest)>& mutate, QString& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    LocalManifest next = manifest_;
    if (!mutate(next)) return true;
    if (!SaveLocalManifest(Path(), next, error)) return false;
    manifest_ = std::move(next);
    return true;
}
