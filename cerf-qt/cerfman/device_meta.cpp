#include "device_meta.h"

#include <cerfcore/core/device_config_keys.h>

namespace {

namespace cfg = cerfcore::config_key;

constexpr char kNotesKey[] = "notes";

int Number(const Json& object, const char* key) { return int(JsonInteger(object, key).value_or(0)); }

QStringList Lines(const Json& object, const char* key) {
    QStringList out;
    const auto  it = object.find(key);
    if (it == object.end() || !it->is_array()) return out;
    for (const auto& item : *it) {
        if (!item.is_string()) continue;
        const QString line = JsonString(item).trimmed();
        if (!line.isEmpty()) out.append(line);
    }
    return out;
}

const Json* Block(const Json& object, const char* key) {
    const auto it = object.find(key);
    return it != object.end() && it->is_object() ? &*it : nullptr;
}

std::optional<int> PositiveNumber(const Json& object, const char* key) {
    const int value = Number(object, key);
    if (value <= 0) return std::nullopt;
    return value;
}

}

QString DeviceMeta::CeVersion() const {
    if (os_ver_major == 0 && os_ver_minor == 0) return QString();
    QString version = QStringLiteral("CE %1.%2").arg(os_ver_major).arg(os_ver_minor);
    if (os_ver_build) version += QStringLiteral(".%1").arg(os_ver_build);
    return version;
}

QString DeviceMeta::DeviceNameOr(const QString& fallback) const {
    return device_name.isEmpty() ? fallback : device_name;
}

QString DeviceMeta::DisplayNameOr(const QString& fallback) const {
    return name.isEmpty() ? DeviceNameOr(fallback) : name;
}

ParsedCerfJson ParseCerfJson(const Json& object) {
    ParsedCerfJson out;
    DeviceMeta&    meta = out.meta;
    if (const Json* m = Block(object, cfg::kMeta)) {
        meta.name        = JsonText(*m, cfg::kName);
        meta.device_name = JsonText(*m, cfg::kDeviceName);
        meta.description = JsonText(*m, "description");
        meta.notes       = Lines(*m, kNotesKey);
        if (const Json* source = Block(*m, "source")) {
            const QString name = JsonText(*source, cfg::kName);
            if (!name.isEmpty())
                meta.source = DeviceSource{name, JsonText(*source, "website"), JsonText(*source, "donate"),
                                           JsonText(*source, "origin"),
                                           JsonBool(*source, "is_community_member").value_or(false)};
        }
        if (const Json* os = Block(*m, cfg::kOs)) {
            meta.os_name      = JsonText(*os, cfg::kName);
            meta.os_ver_major = Number(*os, cfg::kVerMajor);
            meta.os_ver_minor = Number(*os, cfg::kVerMinor);
            meta.os_ver_build = Number(*os, "ver_build");
            meta.os_language  = JsonText(*os, "language");
            meta.os_year      = Number(*os, "year");
            meta.os_notes     = Lines(*os, kNotesKey);
        }
    }
    if (const Json* link = Block(object, kManagerBlockKey))
        meta.forbid_guest_additions = JsonBool(*link, "forbid_guest_additions").value_or(false);
    if (const Json* board = Block(object, cfg::kBoard)) {
        meta.board_id = JsonText(*board, cfg::kId);
        out.width     = PositiveNumber(*board, cfg::kScreenWidth);
        out.height    = PositiveNumber(*board, cfg::kScreenHeight);
    }
    return out;
}
