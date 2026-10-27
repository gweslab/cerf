#include "file_manager_reveal.h"

#include <QProcess>

bool RevealInFileManager(const QString& absolute_path) {
    return QProcess::startDetached(QStringLiteral("open"), {QStringLiteral("-R"), absolute_path});
}
