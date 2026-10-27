#pragma once

#include <QString>

#include <optional>

QString FormatSize(std::optional<qint64> bytes);
