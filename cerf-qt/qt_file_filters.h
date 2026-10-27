#pragma once

#include <cerfcore/host/file_chooser.h>

#include <QStringList>

#include <vector>

QString     NameFilter(const QString& description, const QStringList& patterns);
QStringList FileChooserNameFilters(const std::vector<cerfcore::FileChooserFilter>& filters);
QString     AllFilesNameFilter();
