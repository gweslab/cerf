#include "zip_extract_host.h"

#include <QDir>

#include <string>

zip_t* OpenZipArchive(const QString& path, QString& error) {
    zip_error_t failure;
    zip_error_init(&failure);
    const std::wstring wide   = QDir::toNativeSeparators(path).toStdWString();
    zip_source_t*      source = zip_source_win32w_create(wide.c_str(), 0, -1, &failure);
    zip_t*             archive = source != nullptr ? zip_open_from_source(source, ZIP_RDONLY, &failure) : nullptr;
    if (archive == nullptr) {
        error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(path), QString::fromUtf8(zip_error_strerror(&failure)));
        if (source != nullptr) zip_source_free(source);
    }
    zip_error_fini(&failure);
    return archive;
}

QString HostEntryName(const QString& name) {
    QString host = name;
    host.replace(QLatin1Char('\\'), QLatin1Char('/'));
    return host;
}

bool HostExtractsLinks() { return false; }

bool FinishUnixEntries(const QString&, const std::vector<ZipModeEntry>&, const std::vector<ZipLinkEntry>&,
                       QString&) {
    return true;
}
