#pragma once

#include "manager_operations.h"

#include <QString>

OperationResult CopyHostFile(const QString& source, const QString& destination, const OperationProgress& progress,
                             QString& error);
