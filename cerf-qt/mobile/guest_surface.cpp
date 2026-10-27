#include "guest_surface.h"

#include "../qt_canvas_mouse_buttons.h"
#include "../qt_device_pixels.h"
#include "../qt_emulator_present.h"
#include "../qt_guest_cursor_cache.h"
#include "../qt_key_input.h"
#include "android_haptics.h"
#include "mobile_emulator_window.h"
#include "soft_keyboard_text.h"

#include "../balloon_hint.h"
#include "../hw_screen_renderer.h"
#include "../qt_resource_paths.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/host/frame_renderer.h>
#include <cerfcore/host/keyboard_input.h>
#include <cerfcore/host/keyboard_router.h>
#include <cerfcore/host/pointer_router.h>
#include <cerfcore/host/pointer_source.h>
#include <cerfcore/host/refresh_rate_service.h>
#include <cerfcore/host/relative_mouse_input.h>

#include <QHoverEvent>
#include <QInputMethodEvent>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QQuickWindow>
#include <QTouchEvent>

#include <algorithm>
#include <cmath>

namespace {

constexpr uint32_t kLockedHintMs = 1500;

QString LockedText(ViewMode mode) {
    switch (mode) {
        case ViewMode::FitScreen:   return QStringLiteral("Locked to fit the screen");
        case ViewMode::FitSafeZone: return QStringLiteral("Locked to fit the safe zone");
        default:                    return QStringLiteral("Locked to original scale");
    }
}

}

GuestSurface::GuestSurface(QQuickItem* parent)
    : QQuickPaintedItem(parent),
      key_pacer_([this](const QtHostKey& key, bool key_up) { emu_->Get<QtKeyInput>().Deliver(key, key_up, false); }) {
    setAcceptedMouseButtons(Qt::LeftButton | Qt::RightButton | Qt::MiddleButton);
    setAcceptTouchEvents(true);
    setAcceptHoverEvents(true);
    setFlag(ItemIsFocusScope, false);
    setFlag(ItemAcceptsInputMethod, true);
    setActiveFocusOnTab(false);
    setOpaquePainting(true);
    QObject::connect(&keyboard_, &SoftKeyboardRequest::requestedChanged, this,
                     &GuestSurface::keyboardRequestedChanged);
    QObject::connect(&keyboard_, &SoftKeyboardRequest::offeredChanged, this, &GuestSurface::keyboardButtonChanged);
}

GuestSurface::~GuestSurface() { Detach(); }

void GuestSurface::Attach(cerfcore::CerfEmulator& emu, uint32_t surf_w, uint32_t surf_h) {
    emu_       = &emu;
    presenter_ = std::make_unique<QtFramePresenter>(
        emu.Get<cerfcore::FrameRenderer>(),
        std::make_unique<QtEmulatorPresent>(emu, [this] { return Dpr(); }, [this] { SetFramebufferActive(true); }),
        surf_w, surf_h, fillColor());
    emu.Get<cerffrontend::CanvasInput>().Attach(this);
    placement_.SetSurface(GuestSurfaceWidth(), GuestSurfaceHeight());
    Relayout();
    presenter_->StartRepaints(static_cast<int>(emu.Get<cerfcore::RefreshRateService>().FrameIntervalMs()), [this] {
        RefreshRelativePointer();
        RefreshKeyboardButton();
        update();
    });
    forceActiveFocus(Qt::OtherFocusReason);
}

void GuestSurface::Detach() {
    key_pacer_.Drop();
    if (emu_) {
        gestures_.Cancel();
        gestures_.Flush();
        emu_->Get<cerffrontend::CanvasInput>().Attach(nullptr);
    }
    presenter_.reset();
    emu_ = nullptr;
}

qreal GuestSurface::Dpr() const { return window() ? window()->devicePixelRatio() : 1.0; }

void GuestSurface::paint(QPainter* painter) {
    if (!presenter_) return;
    const qreal dpr    = Dpr();
    const QSize canvas = DeviceCanvasSize(width(), height(), dpr);
    presenter_->DrawTo(*painter, canvas.width(), canvas.height(), dpr);
    if (!cursor_mode_ || relative_pointer_ || !presenter_->Layout().Active()) return;
    auto& guest = emu_->Get<QtGuestCursorCache>();
    if (ActiveKind() == cerfcore::PointerKind::Absolute && guest.Refresh()) {
        if (guest.Drawable())
            overlay_.PaintGuest(*painter, guest.Image(), guest.Hotspot(), cursor_, dpr, placement_.Current().scale);
        return;
    }
    overlay_.PaintArrow(*painter, cursor_, dpr);
}

void GuestSurface::SetGuestSurfaceSize(uint32_t w, uint32_t h) {
    if (!presenter_ || !presenter_->SetGuestSurfaceSize(w, h)) return;
    placement_.SetSurface(GuestSurfaceWidth(), GuestSurfaceHeight());
    ApplyPlacement();
}

uint32_t GuestSurface::GuestSurfaceWidth() const { return presenter_->Layout().SurfaceWidth(); }

uint32_t GuestSurface::GuestSurfaceHeight() const { return presenter_->Layout().SurfaceHeight(); }

void GuestSurface::Refit() { ApplyPlacement(); }

void GuestSurface::SetViewMode(ViewMode mode) {
    placement_.SetMode(mode);
    ApplyPlacement();
}

void GuestSurface::ApplyPlacement() {
    if (!presenter_) return;
    const Placement p = placement_.Current();
    presenter_->Layout().SetPlacement(p.scale, p.x, p.y);
    if (cursor_mode_ && !relative_pointer_) {
        ClampCursor();
        SendCursorMove();
    }
    update();
}

void GuestSurface::SetFramebufferActive(bool active) {
    if (presenter_ && presenter_->Layout().SetActive(active)) update();
}

bool GuestSurface::CaptureSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) {
    return presenter_ && presenter_->Capture(out, w, h);
}

void GuestSurface::Relayout() {
    if (!presenter_) return;
    const qreal dpr    = Dpr();
    const QSize canvas = DeviceCanvasSize(width(), height(), dpr);
    const int   cw     = canvas.width();
    const int   ch     = canvas.height();
    presenter_->SetCanvasSize(cw, ch);
    const int safe_l = DeviceExtent(safe_margins_.left(), dpr);
    const int safe_t = DeviceExtent(safe_margins_.top(), dpr);
    const int safe_r = DeviceExtent(safe_margins_.right(), dpr);
    const int safe_b = DeviceExtent(safe_margins_.bottom(), dpr);
    placement_.SetArea(ViewArea{cw, ch, safe_l, safe_t, safe_r, safe_b});
    emu_->Get<cerffrontend::HwScreenRenderer>().SetTextInsets(safe_l, safe_t, safe_r, safe_b);
    ApplyPlacement();
}

void GuestSurface::SetSafeMargins(const QMarginsF& margins) {
    if (margins == safe_margins_) return;
    safe_margins_ = margins;
    Relayout();
    emit safeMarginsChanged();
}

void GuestSurface::geometryChange(const QRectF& new_geometry, const QRectF& old_geometry) {
    QQuickPaintedItem::geometryChange(new_geometry, old_geometry);
    Relayout();
}

void GuestSurface::itemChange(ItemChange change, const ItemChangeData& value) {
    QQuickPaintedItem::itemChange(change, value);
    if (change == ItemDevicePixelRatioHasChanged || change == ItemSceneChange) Relayout();
}

void GuestSurface::RefreshRelativePointer() {
    const bool relative = ActiveKind() == cerfcore::PointerKind::Relative;
    if (relative == relative_pointer_) return;
    relative_pointer_ = relative;
    emit pointerIconChanged();
    RefreshPointerMenu();
}

void GuestSurface::RefreshKeyboardButton() {
    const cerfcore::KeyboardInput* active = emu_->Get<cerfcore::KeyboardRouter>().Active();
    keyboard_.SetOffered(active != nullptr && active->HasLetterKeys());
}

void GuestSurface::RefreshPointerMenu() {
    const bool has_menu = !emu_->Get<MobileEmulatorWindow>().PointerMenu().empty();
    if (has_menu == pointer_menu_) return;
    pointer_menu_ = has_menu;
    emit pointerMenuChanged();
}

QString GuestSurface::PointerIcon() const {
    const QString name = relative_pointer_ ? QStringLiteral("mouse")
                         : cursor_mode_    ? QString::fromLatin1(kCursorIconName)
                                           : QStringLiteral("stylus");
    return SymbolIconUrl(name);
}

void GuestSurface::SetMouseCapture(bool on) {
    if (on) {
        if (!from_touch_) grabMouse();
        grabbing_ = true;
        return;
    }
    const bool held = grabbing_;
    grabbing_       = false;
    if (!from_touch_) ungrabMouse();
    if (held) emu_->Get<cerffrontend::CanvasInput>().OnCaptureLost();
}

void GuestSurface::FocusCanvas() { forceActiveFocus(Qt::MouseFocusReason); }

void GuestSurface::SetPointerHidden(bool hidden) { setCursor(hidden ? Qt::BlankCursor : Qt::ArrowCursor); }

void GuestSurface::WarpPointerTo(int, int) {}

void GuestSurface::ClientSize(int& width_out, int& height_out) const {
    const qreal dpr = Dpr();
    width_out       = DeviceExtent(width(), dpr);
    height_out      = DeviceExtent(height(), dpr);
}

bool GuestSurface::HostToGuest(int x, int y, int& sx, int& sy) const {
    return presenter_->Layout().HostToGuest(x, y, sx, sy);
}

void GuestSurface::ClampGuest(int& sx, int& sy) const { presenter_->Layout().ClampGuest(sx, sy); }

cerfcore::PointerKind GuestSurface::ActiveKind() const {
    const cerfcore::PointerSource* active = emu_->Get<cerfcore::PointerRouter>().Active();
    return active ? active->Kind() : cerfcore::PointerKind::Absolute;
}

bool GuestSurface::RelativePath() const {
    return relative_held_ != 0 || (held_ == 0 && ActiveKind() == cerfcore::PointerKind::Relative);
}

void GuestSurface::SendCanvasMouse(cerffrontend::CanvasMouse::Kind kind, cerffrontend::MouseButton button,
                                   QPointF device_at, uint32_t held) {
    cerffrontend::CanvasMouse m;
    m.kind   = kind;
    m.button = button;
    m.x      = static_cast<int>(std::lround(device_at.x()));
    m.y      = static_cast<int>(std::lround(device_at.y()));
    m.held   = held;
    emu_->Get<cerffrontend::CanvasInput>().OnMouse(m);
}

void GuestSurface::RouteMouse(QMouseEvent* event, cerffrontend::CanvasMouse::Kind kind) {
    if (!emu_) return;
    if (kind == cerffrontend::CanvasMouse::Kind::kDown && event->buttons() == event->button()) {
        if (relative_mouse_.Held()) relative_mouse_.Release();
        mouse_route_ = MouseRoute::kNone;
    }
    if (mouse_route_ == MouseRoute::kNone)
        mouse_route_ = ActiveKind() == cerfcore::PointerKind::Relative ? MouseRoute::kRelative : MouseRoute::kCanvas;
    const MouseRoute route = mouse_route_;
    if (event->buttons() == Qt::NoButton) mouse_route_ = MouseRoute::kNone;
    if (route == MouseRoute::kRelative) {
        if (kind == cerffrontend::CanvasMouse::Kind::kMove) relative_mouse_.Move(event->position());
        else relative_mouse_.Button(event->button(), kind == cerffrontend::CanvasMouse::Kind::kDown, event->position());
        event->accept();
        return;
    }
    const cerffrontend::MouseButton button =
        kind == cerffrontend::CanvasMouse::Kind::kMove ? cerffrontend::MouseButton::kNone
                                                       : CanvasMouseButton(event->button());
    from_touch_ = false;
    SendCanvasMouse(kind, button, QPointF(DevicePoint(event->position(), Dpr())),
                    HeldMouseButtons(event->buttons()));
    from_touch_ = true;
    event->accept();
}

void GuestSurface::mousePressEvent(QMouseEvent* event) {
    pressed_ = event->buttons() != Qt::NoButton;
    RouteMouse(event, cerffrontend::CanvasMouse::Kind::kDown);
}

void GuestSurface::mouseMoveEvent(QMouseEvent* event) { RouteMouse(event, cerffrontend::CanvasMouse::Kind::kMove); }

void GuestSurface::mouseReleaseEvent(QMouseEvent* event) {
    pressed_ = event->buttons() != Qt::NoButton;
    RouteMouse(event, cerffrontend::CanvasMouse::Kind::kUp);
}

void GuestSurface::hoverEnterEvent(QHoverEvent*) { relative_mouse_.Forget(); }

void GuestSurface::hoverMoveEvent(QHoverEvent* event) {
    if (emu_ && ActiveKind() == cerfcore::PointerKind::Relative) relative_mouse_.Move(event->position());
}

void GuestSurface::hoverLeaveEvent(QHoverEvent*) { relative_mouse_.Forget(); }

void GuestSurface::mouseUngrabEvent() {
    mouse_route_ = MouseRoute::kNone;
    if (emu_) relative_mouse_.Release();
    if (!emu_ || !pressed_) return;
    pressed_ = false;
    SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kCaptureLost, cerffrontend::MouseButton::kNone, QPointF(), 0);
}

void GuestSurface::touchEvent(QTouchEvent* event) {
    if (!emu_) return;
    if (event->type() == QEvent::TouchCancel) {
        gestures_.Cancel();
        event->accept();
        return;
    }
    gestures_.OnTouch(event);
}

void GuestSurface::touchUngrabEvent() {
    if (emu_) gestures_.Cancel();
}

bool GuestSurface::DirectPen() const { return !cursor_mode_ && ActiveKind() != cerfcore::PointerKind::Relative; }

bool GuestSurface::DoubleTapHelper() const { return emu_->Get<cerfcore::DeviceConfig>().double_tap_helper; }

void GuestSurface::PenDown(QPointF at) {
    SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kDown, cerffrontend::MouseButton::kLeft, at * Dpr(),
                    cerffrontend::kHeldLeft);
}

void GuestSurface::PenMove(QPointF at) {
    SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kMove, cerffrontend::MouseButton::kNone, at * Dpr(),
                    cerffrontend::kHeldLeft);
}

void GuestSurface::PenUp(QPointF at) {
    SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kUp, cerffrontend::MouseButton::kLeft, at * Dpr(), 0);
}

void GuestSurface::PenCancel() {
    SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kCaptureLost, cerffrontend::MouseButton::kNone, QPointF(), 0);
}

void GuestSurface::PenRightDown(QPointF at) {
    const QPointF scene = mapToScene(at);
    QMetaObject::invokeMethod(window(), "showTapBubble", Q_ARG(QVariant, scene.x()), Q_ARG(QVariant, scene.y()));
    right_down_at_ = at * Dpr();
    SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kDown, cerffrontend::MouseButton::kRight, right_down_at_,
                    cerffrontend::kHeldRight);
}

void GuestSurface::PenRightUp() {
    SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kUp, cerffrontend::MouseButton::kRight, right_down_at_, 0);
}

QRectF GuestSurface::VisibleImage() const {
    const Placement p = placement_.Current();
    const QRectF    image(p.x, p.y, placement_.SurfaceWidth() * p.scale, placement_.SurfaceHeight() * p.scale);
    const QRectF    shown = image.intersected(QRectF(0, 0, presenter_->Layout().CanvasWidth(),
                                                        presenter_->Layout().CanvasHeight()));
    return shown.isEmpty() ? image : shown;
}

void GuestSurface::ClampCursor() {
    const QRectF shown = VisibleImage();
    cursor_.setX(std::clamp(cursor_.x(), shown.left(), std::max(shown.left(), shown.right() - 1.0)));
    cursor_.setY(std::clamp(cursor_.y(), shown.top(), std::max(shown.top(), shown.bottom() - 1.0)));
}

void GuestSurface::SendCursorMove() {
    SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kMove, cerffrontend::MouseButton::kNone, cursor_, held_);
}

void GuestSurface::SetCursorMode(bool on) {
    if (on == cursor_mode_) return;
    gestures_.Cancel();
    gestures_.Flush();
    cursor_mode_ = on;
    if (on && presenter_) {
        cursor_ = VisibleImage().center();
        SendCursorMove();
    }
    update();
    emit pointerIconChanged();
}

void GuestSurface::PointerMoveBy(QPointF delta) {
    const QPointF device = delta * Dpr();
    if (RelativePath()) {
        const QPointF guest = device / placement_.Current().scale + relative_rest_;
        const int     dx    = static_cast<int>(guest.x());
        const int     dy    = static_cast<int>(guest.y());
        relative_rest_      = guest - QPointF(dx, dy);
        if (dx != 0 || dy != 0) emu_->Get<cerfcore::RelativeMouseInput>().OnRelativeMove(dx, dy, relative_held_);
        return;
    }
    cursor_ += device;
    ClampCursor();
    SendCursorMove();
    update();
}

void GuestSurface::PointerButton(GestureButton button, bool down) {
    const uint32_t relative_bit =
        button == GestureButton::kLeft ? cerfcore::kRelMouseLeft : cerfcore::kRelMouseRight;
    if (down ? RelativePath() : (relative_held_ & relative_bit) != 0) {
        relative_held_ = down ? relative_held_ | relative_bit : relative_held_ & ~relative_bit;
        emu_->Get<cerfcore::RelativeMouseInput>().OnRelativeMove(0, 0, relative_held_);
        return;
    }
    const uint32_t bit = button == GestureButton::kLeft ? cerffrontend::kHeldLeft : cerffrontend::kHeldRight;
    held_              = down ? held_ | bit : held_ & ~bit;
    SendCanvasMouse(down ? cerffrontend::CanvasMouse::Kind::kDown : cerffrontend::CanvasMouse::Kind::kUp,
                    button == GestureButton::kLeft ? cerffrontend::MouseButton::kLeft
                                                   : cerffrontend::MouseButton::kRight,
                    cursor_, held_);
}

void GuestSurface::PinchBegin(QPointF centroid, double distance) {
    placement_.BeginPinch(centroid * Dpr(), distance * Dpr());
}

void GuestSurface::PinchUpdate(QPointF centroid, double distance) {
    const ViewMode before = placement_.Mode();
    placement_.UpdatePinch(centroid * Dpr(), distance * Dpr());
    if (placement_.Mode() != before && placement_.Mode() != ViewMode::FreeForm) PerformThresholdHaptic(*window());
    ApplyPlacement();
}

void GuestSurface::PinchEnd() {
    if (placement_.PinchLocked())
        emu_->Get<MobileEmulatorWindow>().ShowHint(LockedText(placement_.Mode()), kLockedHintMs,
                                                   cerffrontend::BalloonHint::kCanvasBottomGap);
}

void GuestSurface::ToggleKeyboard() { keyboard_.Toggle(); }

Qt::InputMethodHints GuestSurface::InputMethodHints() const {
    return Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase | Qt::ImhMultiLine | Qt::ImhNoFullscreen;
}

QVariant GuestSurface::inputMethodQuery(Qt::InputMethodQuery query) const {
    switch (query) {
        case Qt::ImEnabled:          return true;
        case Qt::ImHints:            return InputMethodHints().toInt();
        case Qt::ImSurroundingText:  return QString();
        case Qt::ImCursorPosition:   return 0;
        case Qt::ImAnchorPosition:   return 0;
        case Qt::ImCursorRectangle:  return QRectF();
        default:                     return QQuickPaintedItem::inputMethodQuery(query);
    }
}

void GuestSurface::RouteKey(const QKeyEvent* event, bool key_up) {
    emu_->Get<QtKeyInput>().RouteTo(event, key_up, [this](const QtHostKey& key, bool up) {
        key_pacer_.Submit(key, up, false);
    });
}

void GuestSurface::inputMethodEvent(QInputMethodEvent* event) {
    if (emu_ && !event->commitString().isEmpty())
        TypeText(event->commitString(), [this](const QtHostKey& key, bool up) { key_pacer_.Submit(key, up, true); });
    event->accept();
}

void GuestSurface::keyPressEvent(QKeyEvent* event) {
    if (event->key() == Qt::Key_Back) {
        event->ignore();
        return;
    }
    if (emu_) RouteKey(event, false);
}

void GuestSurface::keyReleaseEvent(QKeyEvent* event) {
    if (event->key() == Qt::Key_Back) {
        event->ignore();
        return;
    }
    if (emu_) RouteKey(event, true);
}
