#pragma once

#include <QString>

bool    IsDocumentFileValue(const QString& path);
QString ResolveDeviceFileValue(const QString& value, const QString& base_dir);
