#pragma once

#include <QObject>
#include <QtQml/qqmlregistration.h>

class LegacyWindows : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(bool active READ IsActive CONSTANT FINAL)

public:
    using QObject::QObject;

    static bool Active();
    bool        IsActive() const { return Active(); }
};
