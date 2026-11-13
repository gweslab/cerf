#include "guest_surface.h"

#include "qt_canvas_mouse_buttons.h"
#include "qt_device_pixels.h"
#include "guest_canvas_turn.h"
#include "qt_emulator_present.h"
#include "qt_guest_cursor_cache.h"
#include "qt_key_input.h"
#include "qt_emulator_window.h"
#include "surface_area_planner.h"

#include "hud_controls.h"
#include "hw_screen_renderer.h"
#include "qt_resource_paths.h"
#include "CerfStyle/touch_frontend.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/frame_renderer.h>
#include <cerfcore/host/pointer_router.h>
#include <cerfcore/host/pointer_source.h>
#include <cerfcore/host/refresh_rate_service.h>
#include <cerfcore/host/relative_mouse_input.h>

#include <QHoverEvent>
#include <QInputMethodEvent>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QQuickWindow>
#include <QTouchEvent>
#include <QWheelEvent>

#include <cmath>

GuestSurface::GuestSurface(QQuickItem* parent) : FrameViewItem(parent), touch_(TouchFrontend::Active()) {
    setAcceptedMouseButtons(Qt::LeftButton | Qt::RightButton | Qt::MiddleButton);
    setAcceptTouchEvents(touch_);
    setAcceptHoverEvents(true);
    setFlag(ItemIsFocusScope, false);
    setFlag(ItemAcceptsInputMethod, touch_);
    setActiveFocusOnTab(false);
    QObject::connect(&text_.Keyboard(), &SoftKeyboardRequest::requestedChanged, this,
                     &GuestSurface::keyboardRequestedChanged);
    QObject::connect(&text_.Keyboard(), &SoftKeyboardRequest::offeredChanged, this,
                     &GuestSurface::keyboardButtonChanged);
    QObject::connect(&scroll_, &SurfaceScroll::scrolled, this, &QQuickItem::update);
}

GuestSurface::~GuestSurface() { Detach(); }

void GuestSurface::Attach(cerfcore::CerfEmulator& emu, uint32_t surf_w, uint32_t surf_h) {
    gate_.Attach(emu);
    presenter_ = std::make_unique<QtFramePresenter>(std::make_unique<QtEmulatorPresent>(*this), surf_w, surf_h,
                                                    FillColor());
    scroll_.Bind(&presenter_->Layout());
    SyncPlacementSurface();
    Relayout();
    presenter_->StartRepaints(static_cast<int>(emu.Get<cerfcore::RefreshRateService>().FrameIntervalMs()), [this] {
        gate_.Run([this](cerfcore::CerfEmulator& emu) {
            RefreshRelativePointer();
            text_.RefreshOffer();
            presenter_->UiTick(emu);
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
    scroll_.Bind(nullptr);
    presenter_.reset();
    gate_ = cerfcore::InstanceGate();
}

qreal GuestSurface::Dpr() const { return window() ? window()->devicePixelRatio() : 1.0; }

const FrameLayers* GuestSurface::PresentLayers() {
    if (!presenter_) return nullptr;
    const FrameLayers* layers = nullptr;
    gate_.Run([this, &layers](cerfcore::CerfEmulator& emu) {
        const qreal dpr    = Dpr();
        const QSize canvas =
            DeviceCanvasSize(width() - bar_insets_.width(), height() - bar_insets_.height(), PixelScale());
        layers = &presenter_->Present(emu, emu.Get<cerfcore::FrameRenderer>(), canvas.width(), canvas.height(), dpr);
    });
    return layers;
}

bool GuestSurface::CursorShown(cerfcore::CerfEmulator& emu) {
    if (!cursor_mode_ || relative_pointer_ || !presenter_->Layout().Active()) return false;
    auto& guest = emu.Get<QtGuestCursorCache>();
    return ActiveKind() != cerfcore::PointerKind::Absolute || !guest.Refresh() || guest.Drawable();
}

void GuestSurface::PaintCursor(cerfcore::CerfEmulator& emu, QPainter& painter) {
    const qreal dpr   = Dpr();
    auto&       guest = emu.Get<QtGuestCursorCache>();
    if (ActiveKind() == cerfcore::PointerKind::Absolute && guest.Refresh()) {
        if (guest.Drawable())
            overlay_.PaintGuest(
                painter, guest.Image(), guest.Hotspot(),
                emu.Get<cerffrontend::GuestCanvasTurn>().LogicalQuarter(presenter_->Layout().Presentation().quarter),
                pointer_.Position(), dpr, GuestScale());
        return;
    }
    overlay_.PaintArrow(painter, pointer_.Position(), dpr);
}

void GuestSurface::SetGuestSurfaceSize(uint32_t w, uint32_t h) {
    if (!presenter_ || !presenter_->SetGuestSurfaceSize(w, h)) return;
    SyncPlacementSurface();
    Relayout();
}

void GuestSurface::SetPresentation(const cerffrontend::ViewPresentation& presentation) {
    presenter_->Layout().SetPresentation(touch_ ? cerffrontend::ViewPresentation{{}, presentation.quarter} : presentation);
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
    if (touch_) {
        const Placement p = placement_.Current();
        presenter_->Layout().SetPlacement(p.scale, p.x, p.y, placement_.FitZoom(), placement_.CoverZoom());
    }
    if (cursor_mode_ && !relative_pointer_) pointer_.Settle();
    scroll_.Refresh();
    update();
}

void GuestSurface::SetViewportMode(cerffrontend::ViewportMode mode) {
    if (presenter_->Layout().SetMode(mode)) RefreshViewport();
}

void GuestSurface::SetIntegerScale(int factor) {
    if (presenter_->Layout().SetIntegerScale(factor)) RefreshViewport();
}

void GuestSurface::SetFramebufferActive(bool active) {
    if (presenter_ && presenter_->Layout().SetActive(active)) RefreshViewport();
}

void GuestSurface::RefreshViewport() {
    scroll_.Refresh();
    update();
}

bool GuestSurface::CaptureSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) {
    bool captured = false;
    if (presenter_)
        gate_.Run([&](cerfcore::CerfEmulator& emu) {
            captured = presenter_->Capture(emu.Get<cerfcore::FrameRenderer>(), out, w, h);
        });
    return captured;
}

void GuestSurface::RequestShadedCapture() {
    presenter_->RequestShadedCapture();
    update();
}

void GuestSurface::Relayout() {
    if (!presenter_) return;
    const ViewArea a = AreaFor(QSizeF(width(), height()), safe_margins_);
    presenter_->SetCanvasSize(a.width, a.height);
    LOG(Lcd, "GuestSurface: area %dx%d safe %d,%d,%d,%d hud %d,%d,%d,%d\n", a.width, a.height, a.left, a.top, a.right,
        a.bottom, a.hud_left, a.hud_top, a.hud_right, a.hud_bottom);
    placement_.SetArea(a);
    if (touch_)
        gate_.Run([this, &a](cerfcore::CerfEmulator& emu) {
            emu.Get<cerffrontend::HwScreenRenderer>().SetTextInsets(a.left, a.top, a.right, a.bottom);
            emu.Get<cerffrontend::HudControls>().SetCanvasArea(
                cerffrontend::FrameRect{double(a.left), double(a.top), double(a.width - a.left - a.right),
                                        double(a.height - a.top - a.bottom)},
                emu.Get<SurfaceAreaPlanner>().HudMetrics(Dpr()));
        });
    ApplyPlacement();
}

ViewArea GuestSurface::AreaFor(QSizeF logical, const QMarginsF& safe) const {
    if (!touch_) {
        const QSize canvas = DeviceCanvasSize(logical.width(), logical.height(), PixelScale());
        return ViewArea{canvas.width(), canvas.height()};
    }
    ViewArea a;
    gate_.Run([&](cerfcore::CerfEmulator& emu) {
        a = emu.Get<SurfaceAreaPlanner>().AreaFor(logical, safe, PixelScale(), Dpr(), presenter_->Layout());
    });
    return a;
}

QSize GuestSurface::ScreenRegionFor(QSizeF logical, const QMarginsF& safe) const {
    return placement_.RegionFor(AreaFor(logical, safe)).size().toSize();
}

void GuestSurface::SetSafeMargins(const QMarginsF& margins) {
    if (margins == safe_margins_) return;
    safe_margins_ = margins;
    Relayout();
    emit safeMarginsChanged();
}

void GuestSurface::geometryChange(const QRectF& new_geometry, const QRectF& old_geometry) {
    FrameViewItem::geometryChange(new_geometry, old_geometry);
    Relayout();
}

void GuestSurface::itemChange(ItemChange change, const ItemChangeData& value) {
    FrameViewItem::itemChange(change, value);
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
        has_menu = !emu.Get<QtEmulatorWindow>().PointerMenu().empty();
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
        if (!touch_) HoldPointer(true);
        if (!from_touch_) grabMouse();
        grabbing_ = true;
        return;
    }
    const bool held = grabbing_;
    grabbing_       = false;
    if (!touch_ && held) HoldPointer(false);
    if (touch_ && !from_touch_) ungrabMouse();
    if (held) gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::CanvasInput>().OnCaptureLost(); });
}

void GuestSurface::HoldPointer(bool on) {
    QQuickWindow* host = window();
    host->setMouseGrabEnabled(on);
    if (on) {
        host->installEventFilter(this);
        return;
    }
    host->removeEventFilter(this);
    ungrabMouse();
}

bool GuestSurface::eventFilter(QObject* watched, QEvent* event) {
    if (!grabbing_ || event->type() != QEvent::MouseMove) return FrameViewItem::eventFilter(watched, event);
    const auto* move = static_cast<const QMouseEvent*>(event);
    if (move->buttons() != Qt::NoButton) return FrameViewItem::eventFilter(watched, event);
    gate_.Run([this, move](cerfcore::CerfEmulator& emu) {
        host_pointer_.Hover(emu, mapFromScene(move->scenePosition()), presenter_->Layout());
    });
    return true;
}

void GuestSurface::FocusCanvas() { forceActiveFocus(Qt::MouseFocusReason); }

void GuestSurface::SetPointerHidden(bool hidden) { host_pointer_.SetHidden(hidden); }

bool GuestSurface::WarpPointerTo(int x, int y) { return host_pointer_.WarpTo(x, y); }

bool GuestSurface::LockPointer() { return host_pointer_.Lock(); }

void GuestSurface::UnlockPointer() { host_pointer_.Unlock(); }

void GuestSurface::ClientSize(int& width_out, int& height_out) const {
    const QPointF scale = PixelScale();
    width_out           = DeviceExtent(width() - bar_insets_.width(), scale.x());
    height_out          = DeviceExtent(height() - bar_insets_.height(), scale.y());
}

void GuestSurface::SetBarInsets(const QSizeF& insets) {
    if (bar_insets_ == insets) return;
    bar_insets_ = insets;
    emit barInsetsChanged();
    update();
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
        mouse_route_ = touch_ && ActiveKind() == cerfcore::PointerKind::Relative ? MouseRoute::kRelative
                                                                                : MouseRoute::kCanvas;
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
    const QPointF at = QPointF(DevicePoint(event->position(), PixelScale()));
    if (kind != cerffrontend::CanvasMouse::Kind::kUp) ApplyHostCursor(at);
    from_touch_ = false;
    SendCanvasMouse(kind, button, at, HeldMouseButtons(event->buttons()));
    from_touch_ = true;
    event->accept();
}

void GuestSurface::ApplyHostCursor(QPointF device_at) {
    if (touch_) return;
    gate_.Run([this, device_at](cerfcore::CerfEmulator& emu) {
        host_pointer_.ApplyCursor(emu, static_cast<int>(device_at.x()), static_cast<int>(device_at.y()),
                                  presenter_->Layout());
    });
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
    if (!touch_) {
        if (!grabbing_)
            gate_.Run([&](cerfcore::CerfEmulator& emu) { host_pointer_.Hover(emu, event->position(), presenter_->Layout()); });
        return;
    }
    if (gate_.Attached() && !touching_ && ActiveKind() == cerfcore::PointerKind::Relative)
        relative_mouse_.Move(event->position());
}

void GuestSurface::hoverLeaveEvent(QHoverEvent*) {
    relative_mouse_.Forget();
    if (!touch_) gate_.Run([this](cerfcore::CerfEmulator& emu) { host_pointer_.Leave(emu); });
}

void GuestSurface::wheelEvent(QWheelEvent* event) {
    if (touch_) {
        event->ignore();
        return;
    }
    gate_.Run([&](cerfcore::CerfEmulator& emu) { host_pointer_.Wheel(emu, *event); });
}

void GuestSurface::mouseUngrabEvent() {
    mouse_route_ = MouseRoute::kNone;
    if (gate_.Attached()) relative_mouse_.Release();
    if (!gate_.Attached() || !pressed_) return;
    pressed_ = false;
    gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::CanvasInput>().OnPointerLost(); });
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

void GuestSurface::SendRelative(int dx, int dy, uint32_t buttons) {
    const cerffrontend::FramePoint turned =
        presenter_->Layout().Compute().Placement().TurnDelta(cerffrontend::FramePoint{double(dx), double(dy)});
    const int gx = static_cast<int>(turned.x);
    const int gy = static_cast<int>(turned.y);
    gate_.Run([gx, gy, buttons](cerfcore::CerfEmulator& emu) {
        emu.Get<cerfcore::RelativeMouseInput>().OnRelativeMove(gx, gy, buttons);
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
        default:                     return FrameViewItem::inputMethodQuery(query);
    }
}

void GuestSurface::inputMethodEvent(QInputMethodEvent* event) {
    text_.Commit(event);
    event->accept();
}

void GuestSurface::keyPressEvent(QKeyEvent* event) { RouteKey(event, false); }

void GuestSurface::keyReleaseEvent(QKeyEvent* event) { RouteKey(event, true); }

void GuestSurface::RouteKey(QKeyEvent* event, bool key_up) {
    if (touch_) {
        if (!text_.Key(event, key_up)) event->ignore();
        return;
    }
    gate_.Run([event, key_up](cerfcore::CerfEmulator& emu) { emu.Get<QtKeyInput>().Route(event, key_up, true); });
}
