#pragma once

#include "manager_operations.h"

#include <QString>

bool SafeExtract(const QString& zip_path, const QString& destination, QString& error);
QString PreparedBundleRoot(const QString& extract_dir);
OperationResult ExtractPickedArchive(const QString& source, const QString& staging_dir, const QString& destination,
                                     const QString& label, const OperationProgress& progress, QString& error);
