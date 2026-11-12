#pragma once

#include <cerfcore/core/instance_gate.h>

#include "device_pixel_item.h"

#include <QColor>
#include <QImage>
#include <QTimer>
#include <QtQml/qqmlregistration.h>

class StripWidgetBar : public DevicePixelItem {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(QColor backdrop MEMBER backdrop_ NOTIFY backdropChanged)

public:
    explicit StripWidgetBar(QQuickItem* parent = nullptr);

    void Attach(cerfcore::CerfEmulator& emu);
    void Detach();

    void Paint(QPainter* painter) override;

    Q_INVOKABLE void Activate(qreal x, qreal y, bool menu);

signals:
    void backdropChanged();

private:
    void RunWidget(cerfcore::CerfEmulator& emu, qreal x, qreal y, bool menu);
    void Tick();
    int  UnitWidth(cerfcore::CerfEmulator& emu) const;

    cerfcore::InstanceGate gate_;
    QTimer                 tick_;
    QImage                 image_;
    QColor                 backdrop_;
};
