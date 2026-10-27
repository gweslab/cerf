#pragma once

#include <QObject>
#include <QQuickItem>
#include <QSize>
#include <QtQml/qqmlregistration.h>

class DisplayMetrics : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    using QObject::QObject;

    Q_INVOKABLE QSize ScreenPixels(QQuickItem* item) const;
};
