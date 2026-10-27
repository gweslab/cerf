#pragma once

#include <QObject>
#include <QWindow>
#include <QtQml/qqmlregistration.h>

class WindowLifetime : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    using QObject::QObject;

    Q_INVOKABLE void DeleteWhenClosed(QWindow* window) const;
};
