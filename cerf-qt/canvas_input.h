#pragma once

#include <cerfcore/core/service.h>
#include <cerfcore/host/host_pointer_event.h>
#include <cerfcore/host/pointer_source.h>

#include <cstdint>

namespace cerffrontend {

enum class CanvasCursor : uint8_t { kDefault, kHand, kNone, kGuest };

using MouseButton = cerfcore::HostButton;
using cerfcore::kHeldLeft;
using cerfcore::kHeldMiddle;
using cerfcore::kHeldRight;

struct CanvasMouse {
    using Kind = cerfcore::HostPointerEvent::Kind;

    Kind        kind   = Kind::kMove;
    MouseButton button = MouseButton::kNone;
    int         x      = 0;
    int         y      = 0;
    uint32_t    held   = 0;
    int         wheel  = 0;
};

class CanvasInputHost {
public:
    virtual void SetMouseCapture(bool on)                                  = 0;
    virtual bool HasMouseCapture() const                                   = 0;
    virtual void FocusCanvas()                                             = 0;
    virtual void SetPointerHidden(bool hidden)                             = 0;
    virtual bool WarpPointerTo(int x, int y)                               = 0;
    virtual bool LockPointer()                                             = 0;
    virtual void UnlockPointer()                                           = 0;
    virtual void ClientSize(int& width, int& height) const                 = 0;
    virtual bool HostToGuest(int x, int y, int& sx, int& sy) const         = 0;
    virtual void ClampGuest(int& sx, int& sy) const                        = 0;

protected:
    ~CanvasInputHost() = default;
};

class CanvasInput : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;
    void Attach(CanvasInputHost* host) { host_ = host; }

    bool         OnMouse(const CanvasMouse& m);
    bool         OnCaptureLost();
    void         OnPointerLost();
    void         OnPointerLeave();
    void         OnRelativeMotion(int dx, int dy);
    CanvasCursor CursorAt(int x, int y);
    void         OnKey(uint32_t vk, bool key_up);
    void         ReleasePenIfDown();
    void         RefreshLock();
    void         ReleaseGuestInput();

private:
    CanvasInputHost&           Host();
    bool                       GuestInputHeld() const;
    bool                       Locked(bool framebuffer) const;
    void                       EnsureLocked();
    void                       Unlock();
    void                       ShowLockHintOnce();
    cerfcore::HostPointerEvent GuestEvent(const CanvasMouse& m);
    bool                       Dispatch(const CanvasMouse& event);
    bool                       RouteGuest(const CanvasMouse& m);
    bool                       KeepOutsideFramebuffer(const CanvasMouse& m, cerfcore::PointerKind kind);
    bool                       FocusOnPress(const CanvasMouse& m, bool handled);
    void                       FollowPress(bool held_before, bool pressing);

    bool RouteOverlay(const CanvasMouse& m);
    bool RouteLocked(const CanvasMouse& m);
    void SendRelative(int dx, int dy, uint32_t buttons);
    void RecenterLockedPointer();
    void AnchorAt(const CanvasMouse& m);

    CanvasInputHost* host_                = nullptr;
    bool             mouse_locked_active_ = false;
    bool             native_lock_         = false;
    bool             lock_hint_shown_     = false;
    bool             relative_anchored_   = false;
    int              relative_last_x_     = 0;
    int              relative_last_y_     = 0;
};

}
