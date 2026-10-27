#include "desktop_shell.h"

#include "filesystem_path.h"
#include "../link_opener.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QUrl>

REGISTER_SERVICE(DesktopShell);

QString DesktopShell::OpenPath(const QString& path) const {
    const QString target = QFileInfo(path).absoluteFilePath();
    if (!EntryExists(PathOf(target)))
        return QStringLiteral("%1 does not exist.").arg(QDir::toNativeSeparators(target));
    if (!QDesktopServices::openUrl(QUrl::fromLocalFile(target)))
        return QStringLiteral("%1 cannot be opened.").arg(QDir::toNativeSeparators(target));
    return QString();
}

bool DesktopShell::OpenLink(const QString& link) const {
    if (QUrl(link).scheme().isEmpty()) return false;
    emu_.Get<cerffrontend::LinkOpener>().Open(link.toStdString());
    return true;
}
