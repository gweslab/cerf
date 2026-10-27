#pragma once

#include "../qt_emulator_view.h"
#include "../qt_frame_presenter.h"
#include "key_press_pacer.h"
#include "pointer_overlay.h"
#include "relative_mouse_relay.h"
#include "soft_keyboard_request.h"
#include "touch_gestures.h"
#include "view_placement.h"

#include "../canvas_input.h"

#include <QMarginsF>
#include <QPointF>
#include <QQuickPaintedItem>
#include <QtQml/qqmlregistration.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace cerfcore {
class CerfEmulator;
enum class PointerKind;
}

class GuestSurface : public QQuickPaintedItem,
                     public cerffrontend::CanvasInputHost,
                     public TouchGestureHost,
                     public QtEmulatorView {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(QString pointerIcon READ PointerIcon NOTIFY pointerIconChanged)
    Q_PROPERTY(bool pointerMenu READ PointerMenu NOTIFY pointerMenuChanged)
    Q_PROPERTY(bool keyboardButton READ KeyboardButton NOTIFY keyboardButtonChanged)
    Q_PROPERTY(QMarginsF safeMargins READ SafeMargins WRITE SetSafeMargins NOTIFY safeMarginsChanged)
    Q_PROPERTY(Qt::InputMethodHints inputMethodHints READ InputMethodHints CONSTANT)
    Q_PROPERTY(bool keyboardRequested READ KeyboardRequested NOTIFY keyboardRequestedChanged)

public:
    explicit GuestSurface(QQuickItem* parent = nullptr);
    ~GuestSurface() override;

    void Attach(cerfcore::CerfEmulator& emu, uint32_t surf_w, uint32_t surf_h);
    void Detach();

    void paint(QPainter* painter) override;

    void                          SetGuestSurfaceSize(uint32_t w, uint32_t h) override;
    uint32_t                      GuestSurfaceWidth() const override;
    uint32_t                      GuestSurfaceHeight() const override;
    cerffrontend::ViewportLayout& Layout() { return presenter_->Layout(); }
    void                          Refit();
    ViewMode                      CurrentViewMode() const { return placement_.Mode(); }
    void                          SetViewMode(ViewMode mode);
    void                          SetFramebufferActive(bool active) override;
    void                          Repaint() override { update(); }
    bool CaptureSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) override;
    qreal                         Dpr() const override;

    bool      CursorMode() const { return cursor_mode_; }
    void      SetCursorMode(bool on);
    bool      RelativePointer() const { return relative_pointer_; }
    QString   PointerIcon() const;
    bool      PointerMenu() const { return pointer_menu_; }
    bool      KeyboardButton() const { return keyboard_.Offered(); }
    QMarginsF SafeMargins() const { return safe_margins_; }
    void      SetSafeMargins(const QMarginsF& margins);

    Qt::InputMethodHints InputMethodHints() const;
    bool                 KeyboardRequested() const { return keyboard_.Requested(); }

    Q_INVOKABLE void ToggleKeyboard();

    void SetMouseCapture(bool on) override;
    bool HasMouseCapture() const override { return grabbing_; }
    void FocusCanvas() override;
    void SetPointerHidden(bool hidden) override;
    void WarpPointerTo(int x, int y) override;
    void ClientSize(int& width, int& height) const override;
    bool HostToGuest(int x, int y, int& sx, int& sy) const override;
    void ClampGuest(int& sx, int& sy) const override;

    bool DirectPen() const override;
    bool DoubleTapHelper() const override;
    void PenDown(QPointF at) override;
    void PenMove(QPointF at) override;
    void PenUp(QPointF at) override;
    void PenCancel() override;
    void PenRightDown(QPointF at) override;
    void PenRightUp() override;
    void PointerMoveBy(QPointF delta) override;
    void PointerButton(GestureButton button, bool down) override;
    void PinchBegin(QPointF centroid, double distance) override;
    void PinchUpdate(QPointF centroid, double distance) override;
    void PinchEnd() override;

signals:
    void pointerIconChanged();
    void pointerMenuChanged();
    void keyboardButtonChanged();
    void safeMarginsChanged();
    void keyboardRequestedChanged();

protected:
    void     geometryChange(const QRectF& new_geometry, const QRectF& old_geometry) override;
    void     itemChange(ItemChange change, const ItemChangeData& value) override;
    void     mousePressEvent(QMouseEvent* event) override;
    void     mouseMoveEvent(QMouseEvent* event) override;
    void     mouseReleaseEvent(QMouseEvent* event) override;
    void     mouseUngrabEvent() override;
    void     hoverEnterEvent(QHoverEvent* event) override;
    void     hoverMoveEvent(QHoverEvent* event) override;
    void     hoverLeaveEvent(QHoverEvent* event) override;
    void     touchEvent(QTouchEvent* event) override;
    void     touchUngrabEvent() override;
    void     keyPressEvent(QKeyEvent* event) override;
    void     keyReleaseEvent(QKeyEvent* event) override;
    QVariant inputMethodQuery(Qt::InputMethodQuery query) const override;
    void     inputMethodEvent(QInputMethodEvent* event) override;

private:
    void                  RefreshRelativePointer();
    void                  RefreshPointerMenu();
    void                  RefreshKeyboardButton();
    void                  Relayout();
    void                  ApplyPlacement();
    void                  RouteMouse(QMouseEvent* event, cerffrontend::CanvasMouse::Kind kind);
    void                  SendCanvasMouse(cerffrontend::CanvasMouse::Kind kind, cerffrontend::MouseButton button,
                                          QPointF device_at, uint32_t held);
    cerfcore::PointerKind ActiveKind() const;
    bool                  RelativePath() const;
    QRectF                VisibleImage() const;
    void                  ClampCursor();
    void                  SendCursorMove();
    void                  RouteKey(const QKeyEvent* event, bool key_up);

    enum class MouseRoute : uint8_t { kNone, kRelative, kCanvas };

    cerfcore::CerfEmulator*            emu_ = nullptr;
    std::unique_ptr<QtFramePresenter>  presenter_;
    TouchGestures                      gestures_{*this};
    RelativeMouseRelay                 relative_mouse_{*this};
    SoftKeyboardRequest                keyboard_{*this};
    KeyPressPacer                      key_pacer_;
    ViewPlacement                      placement_;
    PointerOverlay                     overlay_;
    QMarginsF                          safe_margins_;
    QPointF                            cursor_;
    QPointF                            relative_rest_;
    QPointF                            right_down_at_;
    uint32_t                           held_             = 0;
    uint32_t                           relative_held_    = 0;
    bool                               cursor_mode_      = false;
    bool                               relative_pointer_ = false;
    bool                               pointer_menu_     = true;
    bool                               grabbing_         = false;
    bool                               from_touch_       = true;
    bool                               pressed_          = false;
    MouseRoute                         mouse_route_      = MouseRoute::kNone;
};
