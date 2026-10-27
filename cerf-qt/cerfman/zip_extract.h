#pragma once

#include <QString>

bool SafeExtract(const QString& zip_path, const QString& destination, QString& error);
QString PreparedBundleRoot(const QString& extract_dir);
