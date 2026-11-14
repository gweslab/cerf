#include "zip_create_host.h"

#include <QFile>

zip_t* CreateZipArchive(const QString& path, QString& error) {
    int    code    = 0;
    zip_t* archive = zip_open(QFile::encodeName(path).constData(), ZIP_CREATE | ZIP_TRUNCATE, &code);
    if (archive != nullptr) return archive;
    zip_error_t failure;
    zip_error_init_with_code(&failure, code);
    error = QStringLiteral("%1: %2").arg(path, QString::fromUtf8(zip_error_strerror(&failure)));
    zip_error_fini(&failure);
    return nullptr;
}
