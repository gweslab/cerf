#pragma once

#include <cerfcore/core/service.h>

#include <cstdint>

namespace cerffrontend {

enum class CanvasCursor : uint8_t { kDefault, kHand, kNone, kGuest };
enum class MouseButton : uint8_t { kNone, kLeft, kRight, kMiddle };

inline constexpr uint32_t kHeldLeft   = 1u << 0;
inline constexpr uint32_t kHeldRight  = 1u << 1;
inline constexpr uint32_t kHeldMiddle = 1u << 2;

struct CanvasMouse {
    enum class Kind : uint8_t { kDown, kUp, kMove, kWheel, kCaptureLost };

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
    virtual void WarpPointerTo(int x, int y)                               = 0;
    virtual void ClientSize(int& width, int& height) const                 = 0;
    virtual bool HostToGuest(int x, int y, int& sx, int& sy) const         = 0;
    virtual void ClampGuest(int& sx, int& sy) const                        = 0;

protected:
    ~CanvasInputHost() = default;
};

class CanvasInput : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void Attach(CanvasInputHost* host) { host_ = host; }

    bool         OnMouse(const CanvasMouse& m);
    bool         OnCaptureLost();
    CanvasCursor CursorAt(int x, int y);
    void         OnKey(uint32_t vk, bool key_up);
    void         ReleasePenIfDown();
    void         RefreshLock();

private:
    CanvasInputHost& Host();
    bool             Locked(bool framebuffer) const;
    void             EnsureLocked();
    void             Unlock();
    void             ShowLockHintOnce();
    void             GuestPoint(const CanvasMouse& m, int& sx, int& sy);
    void             LiftPen(const CanvasMouse& m, bool release_capture);
    void             ReleaseLostButtons(const CanvasMouse& m);
    static uint32_t  RelativeMask(uint32_t held);
    static uint32_t  PointerMask(uint32_t held);

    bool RouteNotification(const CanvasMouse& m);
    bool RouteLocked(const CanvasMouse& m);
    bool RoutePointer(const CanvasMouse& m, bool framebuffer);
    bool RouteStylus(const CanvasMouse& m, bool framebuffer);

    CanvasInputHost* host_                    = nullptr;
    bool             pen_down_                = false;
    bool             mouse_locked_active_     = false;
    bool             lock_hint_shown_         = false;
    uint32_t         notification_click_mask_ = 0;
    uint32_t         pointer_buttons_         = 0;
    uint32_t         relative_buttons_        = 0;
};

}
