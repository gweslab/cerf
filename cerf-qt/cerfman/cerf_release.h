#pragma once

#include <QByteArray>
#include <QString>

#include <optional>

struct CerfRelease {
    QString               tag;
    QString               body;
    QString               html_url;
    QString               asset_name;
    QString               asset_url;
    std::optional<qint64> asset_size;
    std::optional<QString> asset_sha256;
};

std::optional<CerfRelease> ParseStableRelease(const QByteArray& body, const QString& host_branch, QString& error);
std::optional<CerfRelease> ParseCiBuild(const QByteArray& body, const QString& host_branch, QString& error);
bool                       IsNewerVersion(const QString& tag);
