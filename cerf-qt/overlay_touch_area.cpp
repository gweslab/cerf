#include "overlay_touch_area.h"

#include "host_haptics.h"

#include "overlay_input.h"
#include "qt_canvas_mouse_buttons.h"
#include "qt_device_pixels.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QMouseEvent>
#include <QQuickWindow>
#include <QTouchEvent>

using cerffrontend::CanvasMouse;
using cerffrontend::MouseButton;
using cerffrontend::OverlayInput;

namespace {

constexpr OverlayInput::Producer kTouch        = OverlayInput::Producer::kOverlayTouch;
constexpr OverlayInput::Producer kMouse        = OverlayInput::Producer::kOverlayMouse;
constexpr int                    kMousePointer = 0;

}

OverlayTouchArea::OverlayTouchArea(QQuickItem* parent) : QQuickItem(parent) {
    setAcceptTouchEvents(true);
    setAcceptedMouseButtons(Qt::LeftButton | Qt::RightButton | Qt::MiddleButton);
}

void OverlayTouchArea::Attach(cerfcore::CerfEmulator& emu) { gate_.Attach(emu); }

void OverlayTouchArea::Detach() {
    ReleaseAll();
    gate_ = cerfcore::InstanceGate();
}

QPoint OverlayTouchArea::DevicePoint(QPointF at) const { return ::DevicePoint(at, window()->devicePixelRatio()); }

bool OverlayTouchArea::contains(const QPointF& point) const {
    bool         hit = false;
    const QPoint at  = DevicePoint(point);
    gate_.Run([&hit, at](cerfcore::CerfEmulator& emu) { hit = emu.Get<OverlayInput>().Takes(at.x(), at.y()); });
    return hit;
}

void OverlayTouchArea::touchEvent(QTouchEvent* event) {
    gate_.Run([this, event](cerfcore::CerfEmulator& emu) {
        auto& overlay = emu.Get<OverlayInput>();
        for (const QEventPoint& point : event->points()) {
            const QPoint at = DevicePoint(point.position());
            switch (point.state()) {
                case QEventPoint::Pressed:
                    if (overlay.OnPress(kTouch, point.id(), MouseButton::kLeft, at.x(), at.y()) ==
                        OverlayInput::Press::kControl)
                        PerformKeyPressHaptic(*window());
                    break;
                case QEventPoint::Released:
                    if (overlay.OnRelease(kTouch, point.id(), MouseButton::kLeft, true) ==
                        OverlayInput::Release::kControl)
                        PerformKeyReleaseHaptic(*window());
                    break;
                default:
                    overlay.OnMove(kTouch, point.id(), at.x(), at.y());
                    break;
            }
        }
    });
    event->accept();
}

void OverlayTouchArea::touchUngrabEvent() {
    gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<OverlayInput>().CancelAll(kTouch); });
}

void OverlayTouchArea::SendMouse(CanvasMouse::Kind kind, QMouseEvent* event) {
    CanvasMouse m;
    m.kind = kind;
    if (kind != CanvasMouse::Kind::kMove) m.button = CanvasMouseButton(event->button());
    const QPoint at = DevicePoint(event->position());
    m.x             = at.x();
    m.y             = at.y();
    gate_.Run([&m](cerfcore::CerfEmulator& emu) { emu.Get<OverlayInput>().OnMouse(kMouse, kMousePointer, m, true); });
    event->accept();
}

void OverlayTouchArea::mousePressEvent(QMouseEvent* event) { SendMouse(CanvasMouse::Kind::kDown, event); }

void OverlayTouchArea::mouseMoveEvent(QMouseEvent* event) { SendMouse(CanvasMouse::Kind::kMove, event); }

void OverlayTouchArea::mouseReleaseEvent(QMouseEvent* event) { SendMouse(CanvasMouse::Kind::kUp, event); }

void OverlayTouchArea::mouseUngrabEvent() {
    gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<OverlayInput>().CancelAll(kMouse); });
}

void OverlayTouchArea::ReleaseAll() {
    touchUngrabEvent();
    mouseUngrabEvent();
}
