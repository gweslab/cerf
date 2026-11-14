#pragma once

#include <zip.h>

#include <QString>

zip_t* CreateZipArchive(const QString& path, QString& error);
