#pragma once

#include "device_meta.h"
#include "remote_manifest.h"

#include <QString>

#include <optional>
#include <vector>

struct PackageStatus {
    RemotePackage          remote;
    bool                   installed = false;
    std::optional<QString> installed_sha256;

    bool HasUpdate() const;
};

struct DeviceBundle {
    QString                     name;
    QString                     key;
    std::optional<RemoteBundle> remote;
    bool                        local_dir_exists = false;
    std::optional<QString>      installed_sha256;
    DeviceMeta                  meta;
    std::optional<int>          default_screen_width;
    std::optional<int>          default_screen_height;
    std::vector<PackageStatus>  packages;
    std::optional<qint64>       rom_size;
    bool                        cerf_json_pending = false;

    bool    IsInstalled() const { return local_dir_exists; }
    bool    IsUserDevice() const { return local_dir_exists && !remote; }
    bool    HasUpdate() const;
    bool    HasPackageUpdates() const;
    bool    Updatable() const;
    bool    HasAnyUpdate() const;
    QString DeviceName() const;
    QString StateLabel() const;

    const PackageStatus* FindPackage(const QString& category, const QString& package_key) const;
};
