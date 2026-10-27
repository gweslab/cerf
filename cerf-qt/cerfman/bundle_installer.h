#pragma once

#include "manager_operations.h"
#include "remote_manifest.h"

#include <cerfcore/core/service.h>

#include <QString>

#include <optional>

class BundleInstaller : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    ManagerOperations::Job Install(const RemoteBundle& bundle, std::optional<QString> dir_name);
    ManagerOperations::Job InstallPackage(const QString& name, const RemotePackage& package);
    ManagerOperations::Job RefreshCerfJson(const QString& name, const Json& cerf_json);
    ManagerOperations::Job Delete(const QString& name);
    ManagerOperations::Job DeletePackage(const QString& name, const QString& category, const QString& key);

    static QString PackageTargetProblem(const QString& name);

private:
    OperationResult RunInstall(const RemoteBundle& bundle, std::optional<QString> dir_name,
                               const OperationProgress& progress, QString& error);
    OperationResult RunInstallPackage(const QString& name, const RemotePackage& package,
                                      const OperationProgress& progress, QString& error);
    OperationResult DownloadExtract(const QString& url, const QString& label, const QString& temp_dir,
                                    std::optional<qint64> size, std::optional<QString> sha256,
                                    const OperationProgress& progress, QString& prepared, QString& error);
    bool            KeptStorageEntries(const QString& name, const QString& target, const QString& prepared,
                                       QStringList& kept, QString& error) const;
    QString         AllocateDirName(const QString& base) const;
    bool            RecordPackage(const QString& name, const RemotePackage& package, QString& error);
    bool            WriteBundleConfig(const QString& target, const RemoteBundle& bundle, QString& error) const;
};
