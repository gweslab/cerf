#pragma once

#include <QObject>
#include <QtQml/qqmlregistration.h>

class TextMenuSupport : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(bool builtIn READ BuiltIn CONSTANT FINAL)

public:
    using QObject::QObject;

    bool BuiltIn() const;
};
