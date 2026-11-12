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
    Q_PROPERTY(QColor textColor READ TextColor NOTIFY changed FINAL)
    Q_PROPERTY(bool known READ Known NOTIFY changed FINAL)
    Q_PROPERTY(QColor darkColor READ DarkColor NOTIFY changed FINAL)
    Q_PROPERTY(bool darkKnown READ DarkKnown NOTIFY changed FINAL)

public:
    explicit SystemAccent(QObject* parent = nullptr);

    QColor Color() const;
    QColor TextColor() const;
    bool   Known() const;
    QColor DarkColor() const;
    bool   DarkKnown() const;

signals:
    void changed();

private:
    void Refresh();

    HostAccent* host_ = nullptr;
    AccentShade shade_;
    QColor      dark_fill_;
};
