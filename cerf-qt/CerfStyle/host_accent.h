#pragma once

#include <QColor>
#include <QObject>

struct AccentShade {
    QColor fill;
    QColor text;
};

class HostAccent : public QObject {
    Q_OBJECT

public:
    using QObject::QObject;

    AccentShade Shade(bool dark) const;

signals:
    void changed();

protected:
    void Publish(const AccentShade& light, const AccentShade& dark);

protected slots:
    virtual void Reload() = 0;

private:
    AccentShade light_;
    AccentShade dark_;
};

HostAccent* NewHostAccent(QObject* parent);
