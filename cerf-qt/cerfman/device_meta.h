#pragma once

#include "json_file.h"

#include <QString>
#include <QStringList>

#include <optional>

inline constexpr char kManagerBlockKey[] = "launcher";

struct DeviceSource {
    QString name;
    QString website;
    QString donate;
    QString origin;
    bool    is_community_member = false;
};

struct DeviceMeta {
    QString                     name;
    QString                     device_name;
    QString                     board_id;
    QString                     os_name;
    int                         os_ver_major = 0;
    int                         os_ver_minor = 0;
    int                         os_ver_build = 0;
    QString                     os_language;
    int                         os_year = 0;
    QStringList                 os_notes;
    QString                     description;
    QStringList                 notes;
    std::optional<DeviceSource> source;
    bool                        forbid_guest_additions = false;

    QString CeVersion() const;
    QString DeviceNameOr(const QString& fallback) const;
    QString DisplayNameOr(const QString& fallback) const;
};

struct ParsedCerfJson {
    DeviceMeta         meta;
    std::optional<int> width;
    std::optional<int> height;
};

ParsedCerfJson ParseCerfJson(const Json& object);
