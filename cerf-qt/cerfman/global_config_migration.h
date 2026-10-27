#pragma once

#include "json_file.h"

#include <QString>

bool MigrateGlobalConfig(const Json& staged, const QString& installed_path, QString& error);
