#include "picked_document.h"

#include <cerfcore/core/log.h>

QString AdoptPickedDocument(const QUrl& url) {
    LOG(Caution, "FileAccess: cannot open %s (not a local file)\n", qUtf8Printable(url.toString()));
    return QString();
}

bool DeletePickedDocument(const QString& uri) {
    LOG(Caution, "FileAccess: cannot delete %s (not a local file)\n", qUtf8Printable(uri));
    return false;
}
