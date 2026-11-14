#include "file_offer.h"

#include <QDir>
#include <QProcess>

bool OfferFile(const QString& absolute_path, const QString&) {
    QProcess explorer;
    explorer.setProgram(QStringLiteral("explorer.exe"));
    explorer.setNativeArguments(QStringLiteral("/select,\"%1\"").arg(QDir::toNativeSeparators(absolute_path)));
    return explorer.startDetached();
}
