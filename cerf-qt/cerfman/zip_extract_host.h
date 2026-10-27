#pragma once

#include <zip.h>

#include <QString>
#include <QStringList>

#include <cstdint>
#include <vector>

struct ZipLinkEntry {
    QString path;
    QString target;
};

struct ZipModeEntry {
    QString  path;
    uint32_t mode = 0;
};

zip_t*  OpenZipArchive(const QString& path, QString& error);
QString HostEntryName(const QString& name);
bool    HostExtractsLinks();
bool    FinishUnixEntries(const QString& destination, const std::vector<ZipModeEntry>& modes,
                          const std::vector<ZipLinkEntry>& links, QString& error);
