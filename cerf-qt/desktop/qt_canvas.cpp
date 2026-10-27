#include "qt_canvas.h"

#include "../qt_canvas_mouse_buttons.h"
#include "../qt_device_pixels.h"
#include "../qt_emulator_present.h"
#include "../qt_key_input.h"
#include "qt_guest_cursor.h"

#include <cerfcore/host/frame_renderer.h>
#include <cerfcore/host/refresh_rate_service.h>

#include <QCursor>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QWheelEvent>

QtCanvas::QtCanvas(cerfcore::CerfEmulator& emu, QWidget* parent, uint32_t surf_w, uint32_t surf_h)
    : QtPresenterCanvas(emu, parent, emu.Get<cerfcore::FrameRenderer>(), surf_w, surf_h,
                        static_cast<int>(emu.Get<cerfcore::RefreshRateService>().FrameIntervalMs()),
                        std::make_unique<QtEmulatorPresent>(
                            emu, [this] { return Dpr(); }, [this] { SetFramebufferActive(true); })) {
    emu_.Get<cerffrontend::CanvasInput>().Attach(this);
}

QtCanvas::~QtCanvas() {
    emu_.Get<cerffrontend::CanvasInput>().Attach(nullptr);
}

void QtCanvas::ClientSize(int& width, int& height) const {
    int w = 0, h = 0;
    VisibleSize(w, h);
    const qreal  dpr     = Dpr();
    const QPoint landing = DevicePoint(QPointF(LogicalPoint(w / 2, h / 2, dpr)), dpr);
    width                = landing.x() * 2;
    height               = landing.y() * 2;
}

void QtCanvas::SetMouseCapture(bool on) {
    if (on) {
        grabMouse();
        grabbing_ = true;
        return;
    }
    const bool held = grabbing_;
    grabbing_       = false;
    releaseMouse();
    if (held) emu_.Get<cerffrontend::CanvasInput>().OnCaptureLost();
}

void QtCanvas::LoseMouseCapture() {
    if (grabbing_) SetMouseCapture(false);
}

void QtCanvas::FocusCanvas() { setFocus(Qt::MouseFocusReason); }

void QtCanvas::SetPointerHidden(bool hidden) {
    pointer_hidden_ = hidden;
    setCursor(hidden ? Qt::BlankCursor : Qt::ArrowCursor);
}

void QtCanvas::WarpPointerTo(int x, int y) {
    QCursor::setPos(mapToGlobal(LogicalPoint(x, y, Dpr())));
}

void QtCanvas::ApplyCursor(int x, int y) {
    const cerffrontend::CanvasCursor want = emu_.Get<cerffrontend::CanvasInput>().CursorAt(x, y);
    if (pointer_hidden_) {
        setCursor(Qt::BlankCursor);
        return;
    }
    switch (want) {
        case cerffrontend::CanvasCursor::kDefault: setCursor(Qt::ArrowCursor); return;
        case cerffrontend::CanvasCursor::kHand:    setCursor(Qt::PointingHandCursor); return;
        case cerffrontend::CanvasCursor::kNone:    setCursor(Qt::BlankCursor); return;
        case cerffrontend::CanvasCursor::kGuest: {
            bool          active = false;
            const QCursor cur    = emu_.Get<QtGuestCursor>().Resolve(active);
            setCursor(active ? cur : QCursor(Qt::ArrowCursor));
            return;
        }
    }
}

void QtCanvas::RouteMouse(QMouseEvent* event, cerffrontend::CanvasMouse::Kind kind) {
    const QPoint             pos = DevicePoint(event->position(), Dpr());
    cerffrontend::CanvasMouse m;
    m.kind   = kind;
    m.button = kind == cerffrontend::CanvasMouse::Kind::kMove ? cerffrontend::MouseButton::kNone
                                                              : CanvasMouseButton(event->button());
    m.x      = pos.x();
    m.y      = pos.y();
    m.held   = HeldMouseButtons(event->buttons());
    emu_.Get<cerffrontend::CanvasInput>().OnMouse(m);
}

void QtCanvas::mousePressEvent(QMouseEvent* event) {
    const QPoint pos = DevicePoint(event->position(), Dpr());
    ApplyCursor(pos.x(), pos.y());
    RouteMouse(event, cerffrontend::CanvasMouse::Kind::kDown);
}

void QtCanvas::mouseReleaseEvent(QMouseEvent* event) {
    RouteMouse(event, cerffrontend::CanvasMouse::Kind::kUp);
}

void QtCanvas::mouseMoveEvent(QMouseEvent* event) {
    const QPoint pos = DevicePoint(event->position(), Dpr());
    ApplyCursor(pos.x(), pos.y());
    RouteMouse(event, cerffrontend::CanvasMouse::Kind::kMove);
}

void QtCanvas::wheelEvent(QWheelEvent* event) {
    const QPoint             pos = DevicePoint(event->position(), Dpr());
    cerffrontend::CanvasMouse m;
    m.kind  = cerffrontend::CanvasMouse::Kind::kWheel;
    m.x     = pos.x();
    m.y     = pos.y();
    m.held  = HeldMouseButtons(event->buttons());
    m.wheel = event->angleDelta().y();
    emu_.Get<cerffrontend::CanvasInput>().OnMouse(m);
}

void QtCanvas::keyPressEvent(QKeyEvent* event) { emu_.Get<QtKeyInput>().Route(event, false, true); }

void QtCanvas::keyReleaseEvent(QKeyEvent* event) { emu_.Get<QtKeyInput>().Route(event, true, true); }

bool QtCanvas::focusNextPrevChild(bool) { return false; }
