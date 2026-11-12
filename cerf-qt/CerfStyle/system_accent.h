#pragma once

#include "host_accent.h"

#include <QColor>
#include <QObject>
#include <QtQml/qqmlregistration.h>

class SystemAccent : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QColor color READ Color NOTIFY changed FINAL)
    Q_PROPERTY(bool known READ Known NOTIFY changed FINAL)
    Q_PROPERTY(QColor darkColor READ DarkColor NOTIFY changed FINAL)
    Q_PROPERTY(bool darkKnown READ DarkKnown NOTIFY changed FINAL)

public:
    explicit SystemAccent(QObject* parent = nullptr);

    QColor Color() const;
    bool   Known() const;
    QColor DarkColor() const;
    bool   DarkKnown() const;

    Q_INVOKABLE QColor TextOn(const QColor& fill, const QColor& dark_text, const QColor& light_text) const;

signals:
    void changed();

private:
    void Refresh();

    HostAccent* host_ = nullptr;
    QColor      fill_;
    QColor      dark_fill_;
};
