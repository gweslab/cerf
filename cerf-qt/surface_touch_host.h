#pragma once

#include "touch_gestures.h"

#include <QPointF>

class GuestSurface;

class SurfaceTouchHost final : public TouchGestureHost {
public:
    explicit SurfaceTouchHost(GuestSurface& surface) : surface_(surface) {}

    bool  DirectPen() const override;
    bool  DoubleTapHelper() const override;
    qreal Dpr() const override;
    void  PenDown(QPointF at) override;
    void  PenMove(QPointF at) override;
    void  PenUp(QPointF at) override;
    void  PenCancel() override;
    void  PenRightDown(QPointF at) override;
    void  PenRightUp() override;
    void  PointerMoveBy(QPointF delta) override;
    void  PointerButton(GestureButton button, bool down) override;
    void  PinchBegin(QPointF centroid, double distance) override;
    void  PinchUpdate(QPointF centroid, double distance) override;
    void  PinchEnd() override;
    void  ThreeFingerTap() override;

private:
    GuestSurface& surface_;
    QPointF       right_down_at_;
};
