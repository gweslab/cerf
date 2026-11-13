#pragma once

#include "install_retry_gate.h"
#include "json_file.h"

#include <QString>
#include <QStringList>

#include <filesystem>
#include <vector>

class InstallCopier {
public:
    explicit InstallCopier(const InstallRetryGate& gate) : gate_(gate) {}

    bool Prepare(const QString& upgrade_dir, const QString& install_dir, QString& error);
    bool Apply(QString& error);

private:
    using CopyAction = bool (*)(const std::filesystem::path& source, const std::filesystem::path& destination,
                                QString& error);

    bool Step(const QString& title, const QString& what, const InstallRetryGate::Action& action,
              QString& error) const;
    bool ListBundles(QString& error);
    bool ListPayload(QString& error);
    bool ListDroppedFiles(QString& error);
    bool CopyAll(const std::vector<std::filesystem::path>& relatives, CopyAction copy, QString& error);
    bool RemoveDroppedFiles(QString& error);

    const InstallRetryGate&            gate_;
    std::filesystem::path              from_;
    std::filesystem::path              to_;
    Json                               staged_config_;
    std::vector<std::filesystem::path> bundles_;
    std::vector<std::filesystem::path> payload_;
    std::vector<std::filesystem::path> dropped_;
    QStringList                        rejected_;
};
