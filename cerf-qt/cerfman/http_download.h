#pragma once

#include "manager_operations.h"

#include <QByteArray>
#include <QString>

#include <optional>

struct DownloadRequest {
    QString                url;
    QString                destination;
    QString                label;
    std::optional<qint64>  expected_size;
    std::optional<QString> expected_sha256;
    QByteArray             user_agent;
};

OperationResult DownloadVerified(const DownloadRequest& request, const OperationProgress& progress, QString& error);
