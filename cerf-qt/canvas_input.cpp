#include "canvas_input.h"

#include "balloon_hint.h"
#include "canvas_tabs.h"
#include "frontend_window.h"
#include "host_key_binding.h"
#include "input_capture.h"
#include "overlay_input.h"
#include "view_presentation.h"
#include "view_rotation.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/host/host_pointer_input_lock.h>
#include <cerfcore/host/keyboard_router.h>
#include <cerfcore/host/pointer_router.h>
#include <cerfcore/host/pointer_source.h>
#include <cerfcore/host/relative_mouse_input.h>

namespace cerffrontend {

REGISTER_SERVICE(CanvasInput);

namespace {

constexpr uint32_t kLockHintHoldMs = 4500;
constexpr int      kRecenterParts  = 4;
constexpr int      kMousePointer   = 0;

using Kind = CanvasMouse::Kind;
using Tab  = cerfcore::CanvasTab;

}

void CanvasInput::OnReady() {
    emu_.Get<cerfcore::HostPointerInputLock>().RegisterAcquireListener(
        [this] { emu_.Get<FrontendWindow>().RunOnUiThread([this] { ReleaseGuestInput(); }); });
}

CanvasInputHost& CanvasInput::Host() {
    if (!host_) emu_.Get<cerfcore::Fatal>().Die("CanvasInput used with no canvas attached");
    return *host_;
}

bool CanvasInput::Locked(bool framebuffer) const {
    cerfcore::PointerSource* active = emu_.Get<cerfcore::PointerRouter>().Active();
    return active && active->Kind() == cerfcore::PointerKind::Relative && emu_.Get<InputCapture>().IsCaptured() &&
           framebuffer;
}

void CanvasInput::EnsureLocked() {
    if (mouse_locked_active_) return;
    mouse_locked_active_ = true;
    CanvasInputHost& h   = Host();
    h.FocusCanvas();
    h.SetMouseCapture(true);
    h.SetPointerHidden(true);
    native_lock_ = h.LockPointer();
}

void CanvasInput::RecenterLockedPointer() {
    CanvasInputHost& h = Host();
    int              w = 0, ht = 0;
    h.ClientSize(w, ht);
    if (h.WarpPointerTo(w / 2, ht / 2)) relative_anchored_ = false;
}

void CanvasInput::Unlock() {
    if (!mouse_locked_active_) return;
    emu_.Get<cerfcore::PointerRouter>().ReleaseRelative();
    mouse_locked_active_ = false;
    CanvasInputHost& h   = Host();
    if (native_lock_) {
        native_lock_ = false;
        h.UnlockPointer();
    }
    if (h.HasMouseCapture()) h.SetMouseCapture(false);
    h.SetPointerHidden(false);
}

void CanvasInput::ShowLockHintOnce() {
    if (lock_hint_shown_) return;
    lock_hint_shown_ = true;
    emu_.Get<BalloonHint>().ShowUnderCaptureWidget(
        "Mouse locked - press " + emu_.Get<HostKeyBinding>().Label() + " to release",
        kLockHintHoldMs);
}

void CanvasInput::ReleasePenIfDown() {
    auto&      router = emu_.Get<cerfcore::PointerRouter>();
    const bool held   = router.PressHeld();
    router.ReleasePen();
    FollowPress(held, false);
}

void CanvasInput::FollowPress(bool held_before, bool pressing) {
    const bool held = emu_.Get<cerfcore::PointerRouter>().PressHeld();
    if (held == held_before) return;
    CanvasInputHost& h = Host();
    if (held) h.SetMouseCapture(true);
    else if (!pressing && h.HasMouseCapture()) h.SetMouseCapture(false);
}

bool CanvasInput::RouteOverlay(const CanvasMouse& m) {
    return emu_.Get<OverlayInput>().OnMouse(OverlayInput::Producer::kCanvasMouse, kMousePointer, m, false);
}

void CanvasInput::SendRelative(int dx, int dy, uint32_t buttons) {
    const FramePoint turned = FramePlacement(FrameRect{}, emu_.Get<ViewRotation>().PresentedQuarter())
                                  .TurnDelta(FramePoint{double(dx), double(dy)});
    emu_.Get<cerfcore::PointerRouter>().OnRelativeMove(static_cast<int>(turned.x), static_cast<int>(turned.y),
                                                       buttons);
}

cerfcore::HostPointerEvent CanvasInput::GuestEvent(const CanvasMouse& m) {
    cerfcore::HostPointerEvent event;
    event.kind         = m.kind;
    event.button       = m.button;
    event.held         = m.held;
    event.wheel        = m.wheel;
    CanvasInputHost& h = Host();
    event.inside       = h.HostToGuest(m.x, m.y, event.x, event.y);
    h.ClampGuest(event.x, event.y);
    return event;
}

bool CanvasInput::RouteGuest(const CanvasMouse& m) {
    return FocusOnPress(m, emu_.Get<cerfcore::PointerRouter>().Route(GuestEvent(m)));
}

bool CanvasInput::KeepOutsideFramebuffer(const CanvasMouse& m, cerfcore::PointerKind kind) {
    return FocusOnPress(m, kind == cerfcore::PointerKind::Stylus);
}

bool CanvasInput::FocusOnPress(const CanvasMouse& m, bool handled) {
    if (handled && m.kind == Kind::kDown && m.button != MouseButton::kNone) Host().FocusCanvas();
    return handled;
}

bool CanvasInput::RouteLocked(const CanvasMouse& m) {
    const bool lr = (m.kind == Kind::kDown || m.kind == Kind::kUp) &&
                    (m.button == MouseButton::kLeft || m.button == MouseButton::kRight);
    if (m.kind != Kind::kMove && !lr) return false;
    if (!emu_.TryGet<cerfcore::RelativeMouseInput>()) return false;
    EnsureLocked();

    const uint32_t mask = cerfcore::PointerRouter::RelativeButtonsOf(m.held);

    if (m.kind == Kind::kMove) {
        if (native_lock_) return true;
        const int dx = m.x - relative_last_x_;
        const int dy = m.y - relative_last_y_;
        if (relative_anchored_ && (dx != 0 || dy != 0)) SendRelative(dx, dy, mask);
        AnchorAt(m);
        int w = 0, h = 0;
        Host().ClientSize(w, h);
        if (m.x < w / kRecenterParts || m.x > w - w / kRecenterParts || m.y < h / kRecenterParts ||
            m.y > h - h / kRecenterParts)
            RecenterLockedPointer();
        return true;
    }
    emu_.Get<cerfcore::PointerRouter>().OnRelativeMove(0, 0, mask);
    return true;
}

bool CanvasInput::OnCaptureLost() {
    CanvasMouse m;
    m.kind = CanvasMouse::Kind::kCaptureLost;
    return OnMouse(m);
}

void CanvasInput::OnPointerLost() {
    emu_.Get<OverlayInput>().CancelAll(OverlayInput::Producer::kCanvasMouse);
    CanvasInputHost& h = Host();
    if (h.HasMouseCapture()) h.SetMouseCapture(false);
    else                     OnCaptureLost();
}

void CanvasInput::OnPointerLeave() { relative_anchored_ = false; }

void CanvasInput::AnchorAt(const CanvasMouse& m) {
    relative_last_x_   = m.x;
    relative_last_y_   = m.y;
    relative_anchored_ = true;
}

void CanvasInput::OnRelativeMotion(int dx, int dy) {
    RefreshLock();
    if (!mouse_locked_active_) return;
    SendRelative(dx, dy, emu_.Get<cerfcore::PointerRouter>().RelativeButtons());
}

bool CanvasInput::GuestInputHeld() const { return emu_.Get<cerfcore::HostPointerInputLock>().Held(); }

void CanvasInput::ReleaseGuestInput() {
    ReleasePenIfDown();
    emu_.Get<cerfcore::PointerRouter>().ReleasePointerButtons();
    Unlock();
    CanvasInputHost& h = Host();
    if (h.HasMouseCapture()) h.SetMouseCapture(false);
}

bool CanvasInput::OnMouse(const CanvasMouse& event) {
    const bool held    = emu_.Get<cerfcore::PointerRouter>().PressHeld();
    const bool handled = Dispatch(event);
    FollowPress(held, event.kind == Kind::kDown);
    return handled;
}

bool CanvasInput::Dispatch(const CanvasMouse& event) {
    if (GuestInputHeld()) {
        RouteOverlay(event);
        return true;
    }
    auto&                 router      = emu_.Get<cerfcore::PointerRouter>();
    const bool            framebuffer = emu_.Get<CanvasTabs>().Current() == Tab::Framebuffer;
    cerfcore::PointerKind kind        = cerfcore::PointerKind::Absolute;
    if (auto* a = router.Active()) kind = a->Kind();
    const bool locked = Locked(framebuffer);

    CanvasMouse m = event;
    m.held &= ~emu_.Get<OverlayInput>().OwnedHeld(OverlayInput::Producer::kCanvasMouse, kMousePointer);
    if (!locked && (m.kind == Kind::kMove || m.kind == Kind::kDown || m.kind == Kind::kUp)) AnchorAt(m);
    router.ReleaseLost(GuestEvent(m));
    if ((!locked || m.kind != Kind::kDown) && RouteOverlay(event)) return true;

    if (router.PressHeld()) return RouteGuest(m);

    if (locked) {
        if (RouteLocked(m)) return true;
    } else {
        Unlock();
        const bool click = m.kind == Kind::kDown &&
                           (m.button == MouseButton::kLeft || m.button == MouseButton::kRight);
        if (kind == cerfcore::PointerKind::Relative && click && framebuffer) {
            emu_.Get<InputCapture>().SetCaptured(true);
            ShowLockHintOnce();
            return true;
        }
    }
    if (!framebuffer) return KeepOutsideFramebuffer(m, kind);
    return RouteGuest(m);
}

CanvasCursor CanvasInput::CursorAt(int x, int y) {
    const Tab  tab         = emu_.Get<CanvasTabs>().Current();
    const bool framebuffer = tab == Tab::Framebuffer;
    cerfcore::PointerKind kind = cerfcore::PointerKind::Absolute;
    if (auto* a = emu_.Get<cerfcore::PointerRouter>().Active()) kind = a->Kind();
    const bool locked = Locked(framebuffer);

    if (!locked && emu_.Get<OverlayInput>().Takes(x, y)) return CanvasCursor::kHand;

    if (locked) {
        if (emu_.TryGet<cerfcore::RelativeMouseInput>()) {
            EnsureLocked();
            return CanvasCursor::kNone;
        }
    } else {
        Unlock();
    }
    if (framebuffer && kind == cerfcore::PointerKind::Absolute) return CanvasCursor::kGuest;
    return CanvasCursor::kDefault;
}

void CanvasInput::RefreshLock() {
    if (!Locked(emu_.Get<CanvasTabs>().Current() == Tab::Framebuffer)) Unlock();
}

void CanvasInput::OnKey(uint32_t vk, bool key_up) {
    RefreshLock();
    if (key_up || emu_.Get<CanvasTabs>().Current() == Tab::Framebuffer)
        emu_.Get<cerfcore::KeyboardRouter>().OnHostKey(static_cast<uint8_t>(vk), key_up);
}

}
