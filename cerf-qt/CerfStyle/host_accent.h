#pragma once

#include <QColor>
#include <QObject>

class HostAccent : public QObject {
    Q_OBJECT

public:
    using QObject::QObject;

    QColor Fill(bool dark) const;

signals:
    void changed();

protected:
    void Publish(const QColor& light, const QColor& dark);

protected slots:
    virtual void Reload() = 0;

private:
    QColor light_;
    QColor dark_;
};

HostAccent* NewHostAccent(QObject* parent);
