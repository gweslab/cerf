#pragma once

#include "device_bundle.h"

#include <cerfcore/core/service.h>

#include <QString>

#include <optional>
#include <vector>

class DeviceInventory : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    std::vector<DeviceBundle>   List() const;
    std::optional<DeviceBundle>  Find(const QString& name) const;
    std::optional<DeviceBundle>  FindByRemote(const QString& remote_key) const;
    std::optional<PackageStatus> FindPackage(const QString& name, const QString& category, const QString& key) const;
    const RemoteBundle*         LinkedRemote(const QString& device_path) const;
    void                        BackfillInstalledSha256() const;
};
