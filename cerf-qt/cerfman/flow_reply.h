#pragma once

#include <QString>
#include <QVariantMap>

QVariantMap FlowMessage(const QString& title, const QString& message);
QVariantMap FlowError(const QVariantMap& message);
QVariantMap FlowError(const QString& title, const QString& message);
