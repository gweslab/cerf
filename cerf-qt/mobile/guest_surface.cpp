#include "guest_surface.h"

#include "../qt_canvas_mouse_buttons.h"
#include "../qt_device_pixels.h"
#include "../qt_emulator_present.h"
#include "../qt_guest_cursor_cache.h"
#include "android_haptics.h"
#include "mobile_emulator_window.h"

#include "../balloon_hint.h"
#include "../hud_controls.h"
#include "../hud_selection.h"
#include "../hw_screen_renderer.h"
#include "../qt_resource_paths.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/host/frame_renderer.h>
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

GuestSurface::GuestSurface(QQuickItem* parent) : QQuickPaintedItem(parent) {
    setAcceptedMouseButtons(Qt::LeftButton | Qt::RightButton | Qt::MiddleButton);
    setAcceptTouchEvents(true);
    setAcceptHoverEvents(true);
    setFlag(ItemIsFocusScope, false);
    setFlag(ItemAcceptsInputMethod, true);
    setActiveFocusOnTab(false);
    setOpaquePainting(true);
    QObject::connect(&text_.Keyboard(), &SoftKeyboardRequest::requestedChanged, this,
                     &GuestSurface::keyboardRequestedChanged);
    QObject::connect(&text_.Keyboard(), &SoftKeyboardRequest::offeredChanged, this,
                     &GuestSurface::keyboardButtonChanged);
}

GuestSurface::~GuestSurface() { Detach(); }

void GuestSurface::Attach(cerfcore::CerfEmulator& emu, uint32_t surf_w, uint32_t surf_h) {
    gate_.Attach(emu);
    presenter_ = std::make_unique<QtFramePresenter>(std::make_unique<QtEmulatorPresent>(*this), surf_w, surf_h,
                                                    fillColor());
    SyncPlacementSurface();
    Relayout();
    presenter_->StartRepaints(static_cast<int>(emu.Get<cerfcore::RefreshRateService>().FrameIntervalMs()), [this] {
        gate_.Run([this](cerfcore::CerfEmulator&) {
            RefreshRelativePointer();
            text_.RefreshOffer();
        });
        update();
    });
    forceActiveFocus(Qt::OtherFocusReason);
}

void GuestSurface::Detach() {
    text_.Drop();
    if (gate_.Attached()) {
        gestures_.Cancel();
        gestures_.Flush();
    }
    presenter_.reset();
    gate_ = cerfcore::InstanceGate();
}

qreal GuestSurface::Dpr() const { return window() ? window()->devicePixelRatio() : 1.0; }

void GuestSurface::paint(QPainter* painter) {
    if (!presenter_) return;
    gate_.Run([this, painter](cerfcore::CerfEmulator& emu) { PaintFrame(emu, painter); });
}

void GuestSurface::PaintFrame(cerfcore::CerfEmulator& emu, QPainter* painter) {
    const qreal dpr    = Dpr();
    const QSize canvas = DeviceCanvasSize(width(), height(), dpr);
    presenter_->DrawTo(emu, emu.Get<cerfcore::FrameRenderer>(), *painter, canvas.width(), canvas.height(), dpr);
    if (!cursor_mode_ || relative_pointer_ || !presenter_->Layout().Active()) return;
    auto& guest = emu.Get<QtGuestCursorCache>();
    if (ActiveKind() == cerfcore::PointerKind::Absolute && guest.Refresh()) {
        if (guest.Drawable())
            overlay_.PaintGuest(*painter, guest.Image(), guest.Hotspot(), presenter_->Layout().Presentation().quarter,
                                pointer_.Position(), dpr, GuestScale());
        return;
    }
    overlay_.PaintArrow(*painter, pointer_.Position(), dpr);
}

void GuestSurface::SetGuestSurfaceSize(uint32_t w, uint32_t h) {
    if (!presenter_ || !presenter_->SetGuestSurfaceSize(w, h)) return;
    SyncPlacementSurface();
    Relayout();
}

void GuestSurface::SetPresentation(const cerffrontend::ViewPresentation& presentation) {
    presenter_->Layout().SetPresentation(cerffrontend::ViewPresentation{{}, presentation.quarter});
    SyncPlacementSurface();
    Relayout();
}

void GuestSurface::SyncPlacementSurface() {
    const cerffrontend::ViewportLayout& layout = presenter_->Layout();
    placement_.SetSurface(static_cast<uint32_t>(layout.PresentedWidth()), static_cast<uint32_t>(layout.PresentedHeight()));
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
    if (cursor_mode_ && !relative_pointer_) pointer_.Settle();
    update();
}

void GuestSurface::SetFramebufferActive(bool active) {
    if (presenter_ && presenter_->Layout().SetActive(active)) update();
}

bool GuestSurface::CaptureSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) {
    bool captured = false;
    if (presenter_)
        gate_.Run([&](cerfcore::CerfEmulator& emu) {
            captured = presenter_->Capture(emu.Get<cerfcore::FrameRenderer>(), out, w, h);
        });
    return captured;
}

void GuestSurface::Relayout() {
    if (!presenter_) return;
    const QSize canvas = DeviceCanvasSize(width(), height(), Dpr());
    presenter_->SetCanvasSize(canvas.width(), canvas.height());
    const ViewArea a = AreaFor(canvas.width(), canvas.height());
    placement_.SetArea(a);
    gate_.Run([&a](cerfcore::CerfEmulator& emu) {
        emu.Get<cerffrontend::HwScreenRenderer>().SetTextInsets(a.left, a.top, a.right, a.bottom);
        emu.Get<cerffrontend::HudControls>().SetCanvasArea(cerffrontend::FrameRect{
            double(a.left), double(a.top), double(a.width - a.left - a.right), double(a.height - a.top - a.bottom)});
    });
    ApplyPlacement();
}

ViewArea GuestSurface::AreaFor(int canvas_w, int canvas_h) const {
    const qreal dpr = Dpr();
    ViewArea    a{canvas_w, canvas_h, DeviceExtent(safe_margins_.left(), dpr), DeviceExtent(safe_margins_.top(), dpr),
               DeviceExtent(safe_margins_.right(), dpr), DeviceExtent(safe_margins_.bottom(), dpr)};
    const cerffrontend::ViewportLayout& layout = presenter_->Layout();
    cerffrontend::HudInsets             hud;
    gate_.Run([&](cerfcore::CerfEmulator& emu) {
        hud = emu.Get<cerffrontend::HudSelection>().InsideInsets(
            a.width - a.left - a.right, a.height - a.top - a.bottom, layout.Presentation().quarter,
            layout.SurfaceWidth(), layout.SurfaceHeight());
    });
    const auto edge = [](int safe, double depth) { return depth > 0.0 ? safe + static_cast<int>(std::ceil(depth)) : 0; };
    a.hud_left   = edge(a.left, hud.left);
    a.hud_top    = edge(a.top, hud.top);
    a.hud_right  = edge(a.right, hud.right);
    a.hud_bottom = edge(a.bottom, hud.bottom);
    return a;
}

QSize GuestSurface::ScreenRegionFor(QSize canvas) const {
    const ViewArea a = AreaFor(canvas.width(), canvas.height());
    return QSize(a.width - a.hud_left - a.hud_right, a.height - a.hud_top - a.hud_bottom);
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

void GuestSurface::RefreshPointerMenu() {
    bool has_menu = pointer_menu_;
    gate_.Run([&has_menu](cerfcore::CerfEmulator& emu) {
        has_menu = !emu.Get<MobileEmulatorWindow>().PointerMenu().empty();
    });
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
    if (held) gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::CanvasInput>().OnCaptureLost(); });
}

void GuestSurface::FocusCanvas() { forceActiveFocus(Qt::MouseFocusReason); }

void GuestSurface::SetPointerHidden(bool hidden) { setCursor(hidden ? Qt::BlankCursor : Qt::ArrowCursor); }

bool GuestSurface::WarpPointerTo(int, int) { return false; }

bool GuestSurface::LockPointer() { return false; }

void GuestSurface::UnlockPointer() {}

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
    cerfcore::PointerKind kind = cerfcore::PointerKind::Absolute;
    gate_.Run([&kind](cerfcore::CerfEmulator& emu) {
        if (const cerfcore::PointerSource* active = emu.Get<cerfcore::PointerRouter>().Active()) kind = active->Kind();
    });
    return kind;
}

bool GuestSurface::RelativeGuestPointer() const { return ActiveKind() == cerfcore::PointerKind::Relative; }

double GuestSurface::GuestScale() const { return placement_.Current().scale; }

void GuestSurface::SendCanvasMouse(cerffrontend::CanvasMouse::Kind kind, cerffrontend::MouseButton button,
                                   QPointF device_at, uint32_t held) {
    cerffrontend::CanvasMouse m;
    m.kind   = kind;
    m.button = button;
    m.x      = static_cast<int>(std::lround(device_at.x()));
    m.y      = static_cast<int>(std::lround(device_at.y()));
    m.held   = held;
    gate_.Run([&m](cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::CanvasInput>().OnMouse(m); });
}

void GuestSurface::RouteMouse(QMouseEvent* event, cerffrontend::CanvasMouse::Kind kind) {
    if (!gate_.Attached()) return;
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
    if (gate_.Attached() && !touching_ && ActiveKind() == cerfcore::PointerKind::Relative)
        relative_mouse_.Move(event->position());
}

void GuestSurface::hoverLeaveEvent(QHoverEvent*) { relative_mouse_.Forget(); }

void GuestSurface::mouseUngrabEvent() {
    mouse_route_ = MouseRoute::kNone;
    if (gate_.Attached()) relative_mouse_.Release();
    if (!gate_.Attached() || !pressed_) return;
    pressed_ = false;
    SendCanvasMouse(cerffrontend::CanvasMouse::Kind::kCaptureLost, cerffrontend::MouseButton::kNone, QPointF(), 0);
}

void GuestSurface::touchEvent(QTouchEvent* event) {
    if (!gate_.Attached()) return;
    touching_ = event->type() != QEvent::TouchEnd && event->type() != QEvent::TouchCancel;
    if (event->type() == QEvent::TouchCancel) {
        gestures_.Cancel();
        event->accept();
        return;
    }
    gestures_.OnTouch(event);
}

void GuestSurface::touchUngrabEvent() {
    touching_ = false;
    if (gate_.Attached()) gestures_.Cancel();
}

bool GuestSurface::DirectPen() const { return !cursor_mode_ && ActiveKind() != cerfcore::PointerKind::Relative; }

bool GuestSurface::DoubleTapHelper() const {
    bool helper = false;
    gate_.Run([&helper](cerfcore::CerfEmulator& emu) { helper = emu.Get<cerfcore::DeviceConfig>().double_tap_helper; });
    return helper;
}

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
    const QRectF    shown = image.intersected(placement_.ScreenRegion());
    return shown.isEmpty() ? image : shown;
}

void GuestSurface::SetCursorMode(bool on) {
    if (on == cursor_mode_) return;
    gestures_.Cancel();
    gestures_.Flush();
    cursor_mode_ = on;
    if (on && presenter_) pointer_.Center();
    update();
    emit pointerIconChanged();
}

void GuestSurface::PointerMoveBy(QPointF delta) {
    if (pointer_.MoveBy(delta * Dpr())) update();
}

void GuestSurface::SendRelative(int dx, int dy, uint32_t buttons) {
    const cerffrontend::FramePoint turned =
        presenter_->Layout().Compute().Placement().TurnDelta(cerffrontend::FramePoint{double(dx), double(dy)});
    const int gx = static_cast<int>(turned.x);
    const int gy = static_cast<int>(turned.y);
    gate_.Run([gx, gy, buttons](cerfcore::CerfEmulator& emu) {
        emu.Get<cerfcore::RelativeMouseInput>().OnRelativeMove(gx, gy, buttons);
    });
}

void GuestSurface::PointerButton(GestureButton button, bool down) { pointer_.Button(button, down); }

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
    if (!placement_.PinchLocked()) return;
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        emu.Get<MobileEmulatorWindow>().ShowHint(LockedText(placement_.Mode()), kLockedHintMs,
                                                 cerffrontend::BalloonHint::kCanvasBottomGap);
    });
}

void GuestSurface::ToggleKeyboard() { text_.Keyboard().Toggle(); }

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

void GuestSurface::inputMethodEvent(QInputMethodEvent* event) {
    text_.Commit(event);
    event->accept();
}

void GuestSurface::keyPressEvent(QKeyEvent* event) {
    if (!text_.Key(event, false)) event->ignore();
}

void GuestSurface::keyReleaseEvent(QKeyEvent* event) {
    if (!text_.Key(event, true)) event->ignore();
}
