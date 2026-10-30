#pragma once

#include <cerfcore/core/instance_gate.h>

#include <QPoint>
#include <QPointF>
#include <QQuickItem>
#include <QtQml/qqmlregistration.h>

#include <set>

class HudTouchArea : public QQuickItem {
    Q_OBJECT
    QML_ELEMENT

public:
    explicit HudTouchArea(QQuickItem* parent = nullptr);

    void Attach(cerfcore::CerfEmulator& emu);
    void Detach();

    bool contains(const QPointF& point) const override;

protected:
    void touchEvent(QTouchEvent* event) override;
    void touchUngrabEvent() override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void mouseUngrabEvent() override;

private:
    QPoint DevicePoint(QPointF at) const;
    void   ReleaseAll();

    cerfcore::InstanceGate gate_;
    std::set<int>          pointers_;
    bool                   mouse_pressed_ = false;
};
