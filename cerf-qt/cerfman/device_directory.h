#pragma once

#include "device_meta.h"
#include "json_file.h"

#include <QMap>
#include <QString>

#include <functional>
#include <optional>

struct RepositoryLink {
    QString repository_url;
    QString name_on_repository;
};

using FileValues = QMap<QString, QString>;

struct DeviceFiles {
    FileValues rom;
    FileValues storage;
};

class DeviceDirectory {
public:
    explicit DeviceDirectory(QString path) : path_(std::move(path)) {}

    static QString BaseConfigName();
    static QString UserConfigName();
    static QString StorageDefaultFile(const QString& storage_id);
    static QString StorageFile(const QString& value, const QString& storage_id);

    const QString& Path() const { return path_; }
    QString        Name() const;
    QString        FilePath(const QString& name) const;
    QString        ResolveFile(const QString& value) const;

    Json LoadBase() const;
    Json LoadUser() const;

    ParsedCerfJson                ReadMeta() const;
    std::optional<RepositoryLink> ReadLink() const;
    QString                       RomPrimary() const;
    QString                       BoardId() const;
    DeviceFiles                   ReadFiles() const;
    std::pair<Json, Json>         ReadPersistFields() const;

    bool UpdateUser(const std::function<void(Json&)>& mutate, QString& error) const;
    bool WriteLink(const RepositoryLink& link, QString& error) const;
    bool WriteUserName(const QString& name, QString& error) const;
    bool WriteBoardFileOverrides(const QString& board_id, const FileValues& rom,
                                 const FileValues& storage, QString& error) const;
    bool WritePersistOverrides(const Json& fields, QString& error) const;

private:
    FileValues ReadBlock(const char* block, bool with_user) const;

    QString path_;
};
