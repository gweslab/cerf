#include "file_offer.h"

#include <QProcess>

bool OfferFile(const QString& absolute_path) {
    return QProcess::startDetached(QStringLiteral("open"), {QStringLiteral("-R"), absolute_path});
}
