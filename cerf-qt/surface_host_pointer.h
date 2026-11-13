#pragma once

#include "qt_pointer_lock.h"

#include <cerfcore/core/instance_gate.h>

#include <QPointF>

#include <memory>

class QQuickItem;
class QWheelEvent;

namespace cerffrontend {
class ViewportLayout;
}

class SurfaceHostPointer final : public QtRelativeMotionSink {
public:
    SurfaceHostPointer(QQuickItem& item, const cerfcore::InstanceGate& gate);

    void ApplyCursor(cerfcore::CerfEmulator& emu, int x, int y, const cerffrontend::ViewportLayout& layout);
    void Hover(cerfcore::CerfEmulator& emu, QPointF logical_at, const cerffrontend::ViewportLayout& layout);
    void Wheel(cerfcore::CerfEmulator& emu, const QWheelEvent& event);
    void Leave(cerfcore::CerfEmulator& emu);
    void SetHidden(bool hidden);
    bool WarpTo(int x, int y);
    bool Lock();
    void Unlock();

    void    OnRelativeMotion(double dx, double dy) override;
    QPointF RestInWindow() const override;

private:
    qreal   Dpr() const;
    QPointF PixelScale() const;

    QQuickItem&                    item_;
    const cerfcore::InstanceGate&  gate_;
    std::unique_ptr<QtPointerLock> lock_;
    bool                           hidden_ = false;
    double                         rest_x_ = 0;
    double                         rest_y_ = 0;
};
