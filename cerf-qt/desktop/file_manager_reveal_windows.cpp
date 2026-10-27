#include "file_manager_reveal.h"

#include <QDir>
#include <QProcess>

bool RevealInFileManager(const QString& absolute_path) {
    QProcess explorer;
    explorer.setProgram(QStringLiteral("explorer.exe"));
    explorer.setNativeArguments(QStringLiteral("/select,\"%1\"").arg(QDir::toNativeSeparators(absolute_path)));
    return explorer.startDetached();
}
