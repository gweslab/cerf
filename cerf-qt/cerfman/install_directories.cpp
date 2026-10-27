#include "install_directories.h"

#include <cerfcore/core/cerf_paths.h>

#include <QDir>

QString InstallRoot() { return QDir::cleanPath(QString::fromStdString(cerfcore::GetCerfDir())); }

QString StagingDirectory(const QString& install_dir) { return QDir(install_dir).filePath(QStringLiteral("upgrade")); }
