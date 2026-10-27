#pragma once

#include "device_directory.h"
#include "json_file.h"
#include "property_fields.h"

#include <QSize>
#include <QString>

#include <optional>
#include <span>

struct PersistedValues {
    Json baseline;
    Json values;
};

QString         EffectiveMountPoint(const QString& configured, const QString& mount_default);
Json            ResolvePersistBaseline(const Json& base, const QString& mount_default);
PersistedValues ReadPersistedValues(const DeviceDirectory& device, const QString& mount_default);
bool            PersistSubset(const DeviceDirectory& device, const Json& baseline,
                              std::span<const char* const> owned_keys, const Json& current,
                              QString& error);
QSize AutoResolution(std::optional<int> default_width, std::optional<int> default_height,
                     std::optional<QSize> panel);
