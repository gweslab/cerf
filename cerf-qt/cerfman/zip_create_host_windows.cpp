#include "zip_create_host.h"

#include <QDir>

#include <string>

zip_t* CreateZipArchive(const QString& path, QString& error) {
    zip_error_t failure;
    zip_error_init(&failure);
    const std::wstring wide    = QDir::toNativeSeparators(path).toStdWString();
    zip_source_t*      source  = zip_source_win32w_create(wide.c_str(), 0, -1, &failure);
    zip_t*             archive = source != nullptr ? zip_open_from_source(source, ZIP_CREATE | ZIP_TRUNCATE, &failure)
                                                   : nullptr;
    if (archive == nullptr) {
        error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(path), QString::fromUtf8(zip_error_strerror(&failure)));
        if (source != nullptr) zip_source_free(source);
    }
    zip_error_fini(&failure);
    return archive;
}
