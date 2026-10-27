#include "device_file_value.h"

#include <cerfcore/core/cerf_paths.h>

bool IsDocumentFileValue(const QString& path) { return cerfcore::IsHostDocumentPath(path.toStdString()); }

QString ResolveDeviceFileValue(const QString& value, const QString& base_dir) {
    if (base_dir.isEmpty() || value.isEmpty()) return value;
    return QString::fromStdString(cerfcore::ResolveFileIn(base_dir.toStdString(), value.toStdString()));
}
