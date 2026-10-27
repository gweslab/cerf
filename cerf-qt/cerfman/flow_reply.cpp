#include "flow_reply.h"

QVariantMap FlowMessage(const QString& title, const QString& message) {
    return QVariantMap{{QStringLiteral("title"), title}, {QStringLiteral("message"), message}};
}

QVariantMap FlowError(const QVariantMap& message) { return QVariantMap{{QStringLiteral("error"), message}}; }

QVariantMap FlowError(const QString& title, const QString& message) { return FlowError(FlowMessage(title, message)); }
