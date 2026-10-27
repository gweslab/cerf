#include "byte_size_text.h"

QString FormatSize(std::optional<qint64> bytes) {
    if (!bytes || *bytes <= 0) return QString();
    const double n = double(*bytes);
    if (*bytes >= 1024LL * 1024 * 1024) return QStringLiteral("%1 GB").arg(n / (1024.0 * 1024 * 1024), 0, 'f', 1);
    if (*bytes >= 1024LL * 1024) return QStringLiteral("%1 MB").arg(n / (1024.0 * 1024), 0, 'f', 1);
    if (*bytes >= 1024) return QStringLiteral("%1 KB").arg(n / 1024.0, 0, 'f', 0);
    return QStringLiteral("%1 B").arg(*bytes);
}
