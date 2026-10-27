#include "qt_file_filters.h"

QString NameFilter(const QString& description, const QStringList& patterns) {
    return QStringLiteral("%1 (%2)").arg(description, patterns.join(QLatin1Char(' ')));
}

QStringList FileChooserNameFilters(const std::vector<cerfcore::FileChooserFilter>& filters) {
    QStringList parts;
    for (const auto& f : filters)
        parts << NameFilter(QString::fromStdString(f.description),
                            QString::fromStdString(f.patterns).split(QLatin1Char(';')));
    return parts;
}

QString AllFilesNameFilter() { return NameFilter(QStringLiteral("All files"), {QStringLiteral("*")}); }
