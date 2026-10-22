#include "qt_canvas.h"

#include "qt_device_pixels.h"
#include "qt_guest_cursor.h"
#include "qt_key_input.h"
#include "qt_painter.h"

#include <cerffrontend/canvas_tabs.h>
#include <cerffrontend/dpi_scale.h>
#include <cerffrontend/host_virtual_keys.h>
#include <cerffrontend/input_capture.h>
#include <cerffrontend/notification_overlay.h>

#include <cerfcore/host/frame_renderer.h>
#include <cerfcore/host/refresh_rate_service.h>

#include <QCursor>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QWheelEvent>

namespace {

uint32_t Held(Qt::MouseButtons buttons) {
    uint32_t held = 0;
    if (buttons & Qt::LeftButton) held |= cerffrontend::kHeldLeft;
    if (buttons & Qt::RightButton) held |= cerffrontend::kHeldRight;
    if (buttons & Qt::MiddleButton) held |= cerffrontend::kHeldMiddle;
    return held;
}

cerffrontend::MouseButton Button(Qt::MouseButton b) {
    switch (b) {
        case Qt::LeftButton:   return cerffrontend::MouseButton::kLeft;
        case Qt::RightButton:  return cerffrontend::MouseButton::kRight;
        case Qt::MiddleButton: return cerffrontend::MouseButton::kMiddle;
        default:               return cerffrontend::MouseButton::kNone;
    }
}

}

QtCanvas::QtCanvas(cerfcore::CerfEmulator& emu, QWidget* parent, uint32_t surf_w, uint32_t surf_h)
    : QtPresenterCanvas(emu, parent, emu.Get<cerfcore::FrameRenderer>(), surf_w, surf_h,
                        static_cast<int>(emu.Get<cerfcore::RefreshRateService>().FrameIntervalMs())) {
    emu_.Get<cerffrontend::CanvasInput>().Attach(this);
    SetFramebufferActive(emu_.Get<cerffrontend::CanvasTabs>().Current() ==
                         cerffrontend::CanvasTabs::Tab::Framebuffer);
}

QtCanvas::~QtCanvas() {
    emu_.Get<cerffrontend::CanvasInput>().Attach(nullptr);
}

void QtCanvas::OnPresentTick() {
    if (emu_.Get<cerffrontend::CanvasTabs>().OnPresentTick(SourceHasFrame()))
        SetFramebufferActive(true);
    emu_.Get<cerffrontend::CanvasInput>().RefreshLock();
}

bool QtCanvas::RenderAlt(uint32_t* bits, int w, int h) {
    return emu_.Get<cerffrontend::CanvasTabs>().RenderAlt(bits, w, h,
                                                          DeviceExtent(cerffrontend::kDefaultDpi, Dpr()));
}

bool QtCanvas::ShouldDesaturate() {
    return emu_.Get<cerffrontend::CanvasTabs>().ShouldDesaturate();
}

void QtCanvas::RenderOverlay(QImage& present, int w, int h) {
    QPainter  p(&present);
    QtPainter painter(emu_, p);
    emu_.Get<cerffrontend::NotificationOverlay>().Render(painter, w, h,
                                                         DeviceExtent(cerffrontend::kDefaultDpi, Dpr()));
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
    if (!held) return;
    cerffrontend::CanvasMouse m;
    m.kind = cerffrontend::CanvasMouse::Kind::kCaptureLost;
    emu_.Get<cerffrontend::CanvasInput>().OnMouse(m);
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
                                                              : Button(event->button());
    m.x      = pos.x();
    m.y      = pos.y();
    m.held   = Held(event->buttons());
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
    m.held  = Held(event->buttons());
    m.wheel = event->angleDelta().y();
    emu_.Get<cerffrontend::CanvasInput>().OnMouse(m);
}

void QtCanvas::RouteKey(QKeyEvent* event, bool key_up) {
    if (key_up && event->isAutoRepeat()) return;
    QtHostKey key;
    auto&     keys = emu_.Get<QtKeyInput>();
    if (!keys.Translate(event, key)) return;
    keys.ForEachTransition(key, key_up, [&](bool up) { DeliverKey(event, key, up); });
}

void QtCanvas::DeliverKey(QKeyEvent* event, const QtHostKey& key, bool key_up) {
    auto& keys = emu_.Get<QtKeyInput>();
    keys.Note(key, key_up);
    if (emu_.Get<cerffrontend::InputCapture>().OnHostKey(key.sided_vk, key_up)) return;
    const bool system_key = key.vk == cerffrontend::kVkF10 || key.vk == cerffrontend::kVkMenu ||
                            keys.Down(cerffrontend::kVkMenu);
    if (system_key) {
        event->ignore();
        return;
    }
    emu_.Get<cerffrontend::CanvasInput>().OnKey(key.vk, key_up);
}

void QtCanvas::keyPressEvent(QKeyEvent* event) { RouteKey(event, false); }

void QtCanvas::keyReleaseEvent(QKeyEvent* event) { RouteKey(event, true); }

bool QtCanvas::focusNextPrevChild(bool) { return false; }
