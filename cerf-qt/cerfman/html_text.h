#pragma once

#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

class HtmlText : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    using QObject::QObject;

    Q_INVOKABLE QString Link(const QString& url, const QString& text) const;
    Q_INVOKABLE QString Escaped(const QString& text) const;
};
