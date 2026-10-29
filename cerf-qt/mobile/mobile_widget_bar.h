#pragma once

#include <cerfcore/core/instance_gate.h>

#include <QImage>
#include <QQuickPaintedItem>
#include <QTimer>
#include <QtQml/qqmlregistration.h>

class MobileWidgetBar : public QQuickPaintedItem {
    Q_OBJECT
    QML_ELEMENT

public:
    explicit MobileWidgetBar(QQuickItem* parent = nullptr);

    void Attach(cerfcore::CerfEmulator& emu);
    void Detach();

    void paint(QPainter* painter) override;

    Q_INVOKABLE void Activate(qreal x, qreal y, bool menu);

private:
    void RunWidget(cerfcore::CerfEmulator& emu, qreal x, qreal y, bool menu);
    void Tick();
    int  UnitWidth(cerfcore::CerfEmulator& emu) const;

    cerfcore::InstanceGate gate_;
    QTimer                 tick_;
    QImage                 image_;
};
