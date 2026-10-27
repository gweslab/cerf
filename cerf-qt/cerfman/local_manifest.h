#pragma once

#include <QMap>
#include <QString>

#include <optional>
#include <vector>

struct LocalPackageRecord {
    QString category;
    QString key;
    bool                   is_directory = false;
    std::optional<QString> sha256;
};

struct LocalBundleRecord {
    std::optional<QString>          updated_at;
    std::optional<QString>          sha256;
    std::vector<LocalPackageRecord> packages;

    const LocalPackageRecord* FindPackage(const QString& category, const QString& key) const;
    void                      DropPackage(const QString& category, const QString& key);
};

using LocalManifest = QMap<QString, LocalBundleRecord>;

bool LoadLocalManifest(const QString& path, LocalManifest& out, QString& error);
bool SaveLocalManifest(const QString& path, const LocalManifest& manifest, QString& error);
