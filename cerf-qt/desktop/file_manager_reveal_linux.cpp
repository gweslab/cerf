#include "file_manager_reveal.h"

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDesktopServices>
#include <QFileInfo>
#include <QStringList>
#include <QUrl>

namespace {

constexpr int  kCallTimeoutMs  = 5000;
constexpr char kFileManager1[] = "org.freedesktop.FileManager1";

}

bool RevealInFileManager(const QString& absolute_path) {
    QDBusMessage call = QDBusMessage::createMethodCall(
        QString::fromLatin1(kFileManager1), QStringLiteral("/org/freedesktop/FileManager1"),
        QString::fromLatin1(kFileManager1), QStringLiteral("ShowItems"));
    call << QStringList{QUrl::fromLocalFile(absolute_path).toString()} << QString();
    const QDBusMessage reply = QDBusConnection::sessionBus().call(call, QDBus::Block, kCallTimeoutMs);
    return reply.type() == QDBusMessage::ReplyMessage ||
           QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(absolute_path).absolutePath()));
}
