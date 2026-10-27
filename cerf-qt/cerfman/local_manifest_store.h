#pragma once

#include "local_manifest.h"

#include <cerfcore/core/service.h>

#include <QString>

#include <functional>
#include <mutex>
#include <optional>

class LocalManifestStore : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static QString                DevicesDir();
    static QString                DevicePath(const QString& name);
    static QString                RelativeDevicePath(const QString& name);
    static std::optional<QString> SafeDevicePath(const QString& name, QString& error);

    void          Reload();
    LocalManifest Snapshot() const;
    bool          Update(const std::function<bool(LocalManifest& manifest)>& mutate, QString& error);

private:
    QString Path() const;

    mutable std::mutex mutex_;
    LocalManifest      manifest_;
};
