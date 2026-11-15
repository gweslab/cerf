#include "qt_file_filters.h"

QString NameFilter(const QString& description, const QStringList& patterns) {
    return QStringLiteral("%1 (%2)").arg(description, patterns.join(QLatin1Char(' ')));
}

QString AllFilesNameFilter() { return NameFilter(QStringLiteral("All files"), {QStringLiteral("*")}); }
