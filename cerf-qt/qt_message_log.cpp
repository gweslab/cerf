#include "qt_message_log.h"

#include <cerfcore/core/log.h>

#include <QString>
#include <QtLogging>

namespace {

QtMessageHandler g_previous = nullptr;

const char* KindName(QtMsgType type) {
    switch (type) {
        case QtDebugMsg:    return "debug";
        case QtInfoMsg:     return "info";
        case QtWarningMsg:  return "warning";
        case QtCriticalMsg: return "critical";
        case QtFatalMsg:    return "fatal";
    }
    return "message";
}

void ToLog(QtMsgType type, const QMessageLogContext& context, const QString& message) {
    const char*      category = context.category != nullptr ? context.category : "default";
    const QByteArray line =
        QStringLiteral("Qt %1 %2: %3").arg(QLatin1String(category), QLatin1String(KindName(type)), message).toUtf8();
    if (type == QtDebugMsg || type == QtInfoMsg) LOG(Manager, "%s\n", line.constData());
    else                                         LOG(Caution, "%s\n", line.constData());
    g_previous(type, context, message);
}

}

void RouteQtMessagesToLog() { g_previous = qInstallMessageHandler(&ToLog); }
