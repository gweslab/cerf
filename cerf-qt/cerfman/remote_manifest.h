#pragma once

#include "json_file.h"

#include <QByteArray>
#include <QMap>
#include <QPair>
#include <QString>
#include <QUrl>

#include <optional>
#include <vector>

inline constexpr int kSupportedManifestVersion = 2;

struct RemotePackage {
    QString                category;
    QString                key;
    bool                   is_directory = false;
    QString                name;
    QString                archive_path;
    QString                manifest_url;
    std::optional<QString> archive_sha256;
    std::optional<qint64>  archive_size;
    std::optional<qint64>  unpacked_size;

    QString ArchiveUrl() const;
};

struct RemoteBundle {
    QString                    name;
    QString                    repo_url;
    QString                    updated_at;
    QString                    archive_path;
    QString                    manifest_url;
    std::optional<QString>     archive_sha256;
    std::optional<qint64>      archive_size;
    std::optional<qint64>      unpacked_size;
    std::optional<Json>        cerf_json;
    std::vector<RemotePackage> packages;

    QString              ArchiveUrl() const;
    const RemotePackage* FindPackage(const QString& category, const QString& key) const;
};

struct RemoteManifest {
    std::vector<RemoteBundle> bundles;
    std::optional<QString>    abuse_email;
};

struct ManifestVersionMismatch {
    int  remote_version = 0;
    bool remote_is_newer = false;
};

using DownloadPlaces = QMap<QPair<QString, QString>, int>;

QString AppendQuery(const QString& url, const QString& key, const QString& value);
QString CacheBustedUrl(const QUrl& url);
QString PackageCategoryLabel(const QString& category);

bool ParseRemoteManifest(const QByteArray& body, const QString& repo_url, const QString& manifest_url,
                         RemoteManifest& out, std::optional<ManifestVersionMismatch>& mismatch, QString& error);
bool ParseAnalytics(const QByteArray& body, const QString& repo_url, DownloadPlaces& places, QString& error);
