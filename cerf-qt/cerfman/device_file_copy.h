#pragma once

#include "manager_operations.h"

#include <QString>

#include <vector>

class DeviceFileCopy {
public:
    struct File {
        QString source;
        QString name;
        qint64  bytes = 0;
    };

    DeviceFileCopy();

    void    Reserve(const QString& name);
    QString Add(const QString& source);
    void    AddAs(const QString& source, const QString& name);

    const std::vector<File>& Files() const { return files_; }
    qint64                   Bytes() const;
    OperationResult          Run(const QString& target_dir, const OperationProgress& progress, QString& error) const;

private:
    bool    Taken(const QString& name) const;
    QString FreeName(const QString& wanted) const;
    QString Claim(const QString& wanted);

    std::vector<QString> taken_;
    std::vector<File>    files_;
};
