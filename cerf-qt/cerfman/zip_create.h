#pragma once

#include "manager_operations.h"

#include <zip.h>

#include <QString>

class ZipCreator {
public:
    explicit ZipCreator(QString path) : path_(std::move(path)) {}
    ~ZipCreator();
    ZipCreator(const ZipCreator&)            = delete;
    ZipCreator& operator=(const ZipCreator&) = delete;

    bool            Open(QString& error);
    bool            AddFile(const QString& entry, const QString& source, QString& error);
    OperationResult Close(const QString& label, const OperationProgress& progress, QString& error);

private:
    QString ArchiveFailure() const;

    QString path_;
    zip_t*  archive_ = nullptr;
    qint64  total_   = 0;
    QString source_failure_;
};
