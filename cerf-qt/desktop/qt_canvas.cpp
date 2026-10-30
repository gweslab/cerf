#include "qt_canvas.h"

#include "../qt_canvas_mouse_buttons.h"
#include "../qt_device_pixels.h"
#include "../qt_emulator_present.h"
#include "../qt_key_input.h"
#include "qt_guest_cursor.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/frame_renderer.h>
#include <cerfcore/host/guest_resize_policy.h>
#include <cerfcore/host/refresh_rate_service.h>

#include <QCursor>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QResizeEvent>
#include <QWheelEvent>

#include <algorithm>
#include <cmath>

namespace {

constexpr int kResizeDebounceMs = 200;

int WholeScale(double scale) { return std::max(1, static_cast<int>(std::lround(scale))); }

}

QtCanvas::QtCanvas(cerfcore::CerfEmulator& emu, QWidget* parent, uint32_t surf_w, uint32_t surf_h)
    : QtPresenterCanvas(emu, parent, surf_w, surf_h,
                        static_cast<int>(emu.Get<cerfcore::RefreshRateService>().FrameIntervalMs())) {
    SetPresentHooks(std::make_unique<QtEmulatorPresent>(*this));
    pointer_lock_ = MakeQtPointerLock(*this);
    resize_debounce_.setSingleShot(true);
    resize_debounce_.setInterval(kResizeDebounceMs);
    QObject::connect(&resize_debounce_, &QTimer::timeout, this,
                     [this] { gate_.Run([this](cerfcore::CerfEmulator& gate_emu) { FireAutoResize(gate_emu); }); });
}

void QtCanvas::resizeEvent(QResizeEvent* event) {
    QtPresenterCanvas::resizeEvent(event);
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        auto* policy = emu.TryGet<cerfcore::GuestResizePolicy>();
        if (policy && policy->Enabled() && !window()->isMinimized()) resize_debounce_.start();
    });
}

void QtCanvas::FireAutoResize(cerfcore::CerfEmulator& emu) {
    const qreal dpr = Dpr();
    if (auto* policy = emu.TryGet<cerfcore::GuestResizePolicy>())
        policy->OnUserResizeEnd(static_cast<uint32_t>(DeviceExtent(width(), dpr)),
                                static_cast<uint32_t>(DeviceExtent(height(), dpr)));
}

cerfcore::FrameSource& QtCanvas::Source(cerfcore::CerfEmulator& emu) { return emu.Get<cerfcore::FrameRenderer>(); }

void QtCanvas::ClientSize(int& width, int& height) const { VisibleSize(width, height); }

void QtCanvas::SetMouseCapture(bool on) {
    if (on) {
        grabMouse();
        grabbing_ = true;
        return;
    }
    const bool held = grabbing_;
    grabbing_       = false;
    releaseMouse();
    if (held) gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::CanvasInput>().OnCaptureLost(); });
}

void QtCanvas::LoseMouseCapture() {
    if (grabbing_) SetMouseCapture(false);
}

void QtCanvas::FocusCanvas() { setFocus(Qt::MouseFocusReason); }

void QtCanvas::SetPointerHidden(bool hidden) {
    pointer_hidden_ = hidden;
    setCursor(hidden ? Qt::BlankCursor : Qt::ArrowCursor);
}

bool QtCanvas::WarpPointerTo(int x, int y) {
    if (!pointer_lock_->CanWarp()) return false;
    const QPoint target = mapToGlobal(LogicalPoint(x, y, Dpr()));
    if (QCursor::pos() == target) return false;
    QCursor::setPos(target);
    return true;
}

bool QtCanvas::LockPointer() {
    relative_rest_x_ = 0;
    relative_rest_y_ = 0;
    return pointer_lock_->Lock(*this);
}

void QtCanvas::UnlockPointer() { pointer_lock_->Unlock(); }

void QtCanvas::OnRelativeMotion(double dx, double dy) {
    const qreal dpr = Dpr();
    relative_rest_x_ += dx * dpr;
    relative_rest_y_ += dy * dpr;
    const int ix = static_cast<int>(relative_rest_x_);
    const int iy = static_cast<int>(relative_rest_y_);
    relative_rest_x_ -= ix;
    relative_rest_y_ -= iy;
    if (ix == 0 && iy == 0) return;
    gate_.Run([ix, iy](cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::CanvasInput>().OnRelativeMotion(ix, iy); });
}

void QtCanvas::ApplyCursor(cerfcore::CerfEmulator& emu, int x, int y) {
    const cerffrontend::CanvasCursor want = emu.Get<cerffrontend::CanvasInput>().CursorAt(x, y);
    if (pointer_hidden_) {
        setCursor(Qt::BlankCursor);
        return;
    }
    switch (want) {
        case cerffrontend::CanvasCursor::kDefault: setCursor(Qt::ArrowCursor); return;
        case cerffrontend::CanvasCursor::kHand:    setCursor(Qt::PointingHandCursor); return;
        case cerffrontend::CanvasCursor::kNone:    setCursor(Qt::BlankCursor); return;
        case cerffrontend::CanvasCursor::kGuest: {
            double sx = 0.0;
            double sy = 0.0;
            GuestPixelScale(sx, sy);
            const QtGuestCursorLook look{WholeScale(sx), WholeScale(sy), Quarter(), Dpr()};
            bool                    active = false;
            const QCursor           cur    = emu.Get<QtGuestCursor>().Resolve(look, active);
            setCursor(active ? cur : QCursor(Qt::ArrowCursor));
            return;
        }
    }
}

void QtCanvas::RouteMouse(cerfcore::CerfEmulator& emu, QMouseEvent* event, cerffrontend::CanvasMouse::Kind kind) {
    const QPoint             pos = DevicePoint(event->position(), Dpr());
    cerffrontend::CanvasMouse m;
    m.kind   = kind;
    m.button = kind == cerffrontend::CanvasMouse::Kind::kMove ? cerffrontend::MouseButton::kNone
                                                              : CanvasMouseButton(event->button());
    m.x      = pos.x();
    m.y      = pos.y();
    m.held   = HeldMouseButtons(event->buttons());
    emu.Get<cerffrontend::CanvasInput>().OnMouse(m);
}

void QtCanvas::mousePressEvent(QMouseEvent* event) {
    gate_.Run([this, event](cerfcore::CerfEmulator& emu) {
        const QPoint pos = DevicePoint(event->position(), Dpr());
        ApplyCursor(emu, pos.x(), pos.y());
        RouteMouse(emu, event, cerffrontend::CanvasMouse::Kind::kDown);
    });
}

void QtCanvas::mouseReleaseEvent(QMouseEvent* event) {
    gate_.Run([this, event](cerfcore::CerfEmulator& emu) { RouteMouse(emu, event, cerffrontend::CanvasMouse::Kind::kUp); });
}

void QtCanvas::mouseMoveEvent(QMouseEvent* event) {
    gate_.Run([this, event](cerfcore::CerfEmulator& emu) {
        const QPoint pos = DevicePoint(event->position(), Dpr());
        ApplyCursor(emu, pos.x(), pos.y());
        RouteMouse(emu, event, cerffrontend::CanvasMouse::Kind::kMove);
    });
}

void QtCanvas::leaveEvent(QEvent*) {
    gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::CanvasInput>().OnPointerLeave(); });
}

void QtCanvas::wheelEvent(QWheelEvent* event) {
    gate_.Run([this, event](cerfcore::CerfEmulator& emu) {
        const QPoint             pos = DevicePoint(event->position(), Dpr());
        cerffrontend::CanvasMouse m;
        m.kind  = cerffrontend::CanvasMouse::Kind::kWheel;
        m.x     = pos.x();
        m.y     = pos.y();
        m.held  = HeldMouseButtons(event->buttons());
        m.wheel = event->angleDelta().y();
        emu.Get<cerffrontend::CanvasInput>().OnMouse(m);
    });
}

void QtCanvas::keyPressEvent(QKeyEvent* event) {
    gate_.Run([event](cerfcore::CerfEmulator& emu) { emu.Get<QtKeyInput>().Route(event, false, true); });
}

void QtCanvas::keyReleaseEvent(QKeyEvent* event) {
    gate_.Run([event](cerfcore::CerfEmulator& emu) { emu.Get<QtKeyInput>().Route(event, true, true); });
}

bool QtCanvas::focusNextPrevChild(bool) { return false; }
