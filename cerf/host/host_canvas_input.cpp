#define NOMINMAX

#include "host_canvas_input.h"

#include "../core/cerf_emulator.h"
#include "boot_screen.h"
#include "host_balloon_hint.h"
#include "host_canvas.h"
#include "host_guest_cursor.h"
#include "host_input_capture.h"
#include "host_key_binding.h"
#include "keyboard_router.h"
#include "memory_visualizer.h"
#include "pointer_input.h"
#include "pointer_router.h"
#include "pointer_source.h"
#include "pointer_stylus_simulation.h"
#include "relative_mouse_input.h"
#include "stylus_alt_tap.h"
#include "touch_input.h"

REGISTER_SERVICE(HostCanvasInput);

namespace { constexpr UINT kLockHintHoldMs = 4500; }

void HostCanvasInput::ReleasePenIfDown() {
    emu_.Get<StylusAltTap>().Cancel();
    if (!pen_down_) return;
    pen_down_ = false;
    if (GetCapture() == emu_.Get<HostCanvas>().Hwnd()) ReleaseCapture();
    if (auto* t = emu_.TryGet<TouchInput>()) t->OnCaptureLost();
}

bool HostCanvasInput::RoutePointerInput(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* pi = emu_.TryGet<PointerInput>();
    auto& hc = emu_.Get<HostCanvas>();
    if (!pi || hc.CurrentTab() != HostCanvas::Tab::Framebuffer) return false;

    if (msg == WM_MOUSEWHEEL) {
        POINT p = { (int)(short)LOWORD(lp), (int)(short)HIWORD(lp) };
        ScreenToClient(hwnd, &p);   /* wheel lp is screen, not client */
        int sx, sy;
        hc.HostToGuest(p.x, p.y, sx, sy);
        hc.ClampGuest(sx, sy);
        pi->OnWheel(sx, sy, (int)(short)HIWORD(wp));
        return true;
    }
    if (msg == WM_CAPTURECHANGED) { pi->OnCaptureLost(); return true; }

    const bool down = msg == WM_LBUTTONDOWN || msg == WM_RBUTTONDOWN || msg == WM_MBUTTONDOWN;
    const bool up   = msg == WM_LBUTTONUP   || msg == WM_RBUTTONUP   || msg == WM_MBUTTONUP;
    if (!down && !up && msg != WM_MOUSEMOVE) return false;

    if (down) { SetFocus(hwnd); SetCapture(hwnd); }

    int sx, sy;
    hc.HostToGuest((int)(short)LOWORD(lp), (int)(short)HIWORD(lp), sx, sy);
    hc.ClampGuest(sx, sy);

    const WORD ks = LOWORD(wp);
    uint32_t mask = 0;
    if (ks & MK_LBUTTON) mask |= kPointerLeft;
    if (ks & MK_RBUTTON) mask |= kPointerRight;
    if (ks & MK_MBUTTON) mask |= kPointerMiddle;

    const bool held   = (mask & (kPointerLeft | kPointerRight)) != 0;
    const bool report = down || up || held ||
                        !emu_.Get<PointerStylusSimulation>().Enabled();
    if (report) pi->OnMove(sx, sy, mask);

    if (up && mask == 0) ReleaseCapture();
    return true;
}

void HostCanvasInput::WarpToCentre(HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    POINT c = { (rc.right - rc.left) / 2, (rc.bottom - rc.top) / 2 };
    ClientToScreen(hwnd, &c);
    SetCursorPos(c.x, c.y);
}

void HostCanvasInput::ShowLockHintOnce() {
    if (lock_hint_shown_) return;
    lock_hint_shown_ = true;
    const std::wstring hint = L"Mouse locked - press " +
                              emu_.Get<HostKeyBinding>().Label() +
                              L" to release";
    emu_.Get<HostBalloonHint>().ShowUnderCaptureWidget(hint.c_str(),
                                                       kLockHintHoldMs);
}

bool HostCanvasInput::RouteCapturedMouse(HWND hwnd, UINT msg, WPARAM wp,
                                         LPARAM lp, LRESULT& out) {
    const bool is_mouse =
        msg == WM_MOUSEMOVE || msg == WM_SETCURSOR ||
        msg == WM_LBUTTONDOWN || msg == WM_RBUTTONDOWN ||
        msg == WM_LBUTTONUP   || msg == WM_RBUTTONUP;
    if (!is_mouse) return false;

    auto* rm = emu_.TryGet<RelativeMouseInput>();
    if (!rm) return false;   /* board has no relative pointer device */

    if (!mouse_locked_active_) {
        mouse_locked_active_ = true;
        SetFocus(hwnd);
        SetCapture(hwnd);
        ShowCursor(FALSE);
        WarpToCentre(hwnd);
    }

    if (msg == WM_SETCURSOR && LOWORD(lp) == HTCLIENT) { out = TRUE; return true; }

    uint32_t mask = 0;
    const WORD ks = LOWORD(wp);
    if (ks & MK_LBUTTON) mask |= kRelMouseLeft;
    if (ks & MK_RBUTTON) mask |= kRelMouseRight;

    if (msg == WM_MOUSEMOVE) {
        RECT rc;
        GetClientRect(hwnd, &rc);
        const int dx = (int)(short)LOWORD(lp) - (rc.right - rc.left) / 2;
        const int dy = (int)(short)HIWORD(lp) - (rc.bottom - rc.top) / 2;
        if (dx == 0 && dy == 0) return true;   /* our own warp */
        rm->OnRelativeMove(dx, dy, mask);
        WarpToCentre(hwnd);
        return true;
    }

    rm->OnRelativeMove(0, 0, mask);   /* button transition, no motion */
    return true;
}

bool HostCanvasInput::Handle(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, LRESULT& out) {
    auto& hc = emu_.Get<HostCanvas>();
    out = 0;

    if (msg == WM_TIMER && emu_.Get<StylusAltTap>().OnTimer(wp)) return true;

    const bool framebuffer = hc.CurrentTab() == HostCanvas::Tab::Framebuffer;

    if (hc.CurrentTab() == HostCanvas::Tab::Boot) {
        auto& boot = emu_.Get<BootScreen>();
        if (msg == WM_SETCURSOR && LOWORD(lp) == HTCLIENT) {
            POINT p;
            GetCursorPos(&p);
            ScreenToClient(hwnd, &p);
            if (boot.HitTestHwLine(p.x, p.y)) {
                SetCursor(LoadCursorW(nullptr, IDC_HAND));
                out = TRUE;
                return true;
            }
        } else if (msg == WM_LBUTTONDOWN &&
                   boot.HitTestHwLine((int)(short)LOWORD(lp), (int)(short)HIWORD(lp))) {
            hc.SetTab(HostCanvas::Tab::Hw, /*user_initiated=*/true);
            return true;
        }
    }

    PointerKind kind = PointerKind::Absolute;
    if (auto* a = emu_.Get<PointerRouter>().Active()) kind = a->Kind();
    const bool relative_active = kind == PointerKind::Relative;
    const bool stylus_active   = kind == PointerKind::Stylus;

    /* The host-capture mouse lock (click-to-lock, hidden cursor, warp-to-centre,
       relative deltas) engages ONLY when a Relative source is the active device;
       for Absolute/Stylus the whole lock path stays off. Right-Ctrl keyboard
       capture is independent of this and works in every mode. */
    auto* cap = emu_.TryGet<HostInputCapture>();
    const bool locked = relative_active && cap && cap->IsCaptured() && framebuffer;
    if (locked) {
        if (RouteCapturedMouse(hwnd, msg, wp, lp, out)) return true;
    } else {
        if (mouse_locked_active_) {
            mouse_locked_active_ = false;
            if (GetCapture() == hwnd) ReleaseCapture();
            ShowCursor(TRUE);
        }
        const bool click = msg == WM_LBUTTONDOWN || msg == WM_RBUTTONDOWN;
        if (relative_active && click && cap && framebuffer) {
            cap->SetCaptured(true);
            ShowLockHintOnce();
            return true;
        }
    }

    /* vmware-cursor model: host cursor becomes the guest's shape (NULL when the
       guest hid it). Gate on Absolute - in stylus/relative mode the guest cursor
       isn't driven, and HostGuestCursor's latched-hidden state would SetCursor(NULL)
       and blank the host cursor, leaving nothing to aim taps with. */
    if (msg == WM_SETCURSOR && LOWORD(lp) == HTCLIENT && framebuffer &&
        kind == PointerKind::Absolute) {
        bool active = false;
        HCURSOR cur = emu_.Get<HostGuestCursor>().Resolve(active);
        if (active) {
            SetCursor(cur);
            out = TRUE;
            return true;
        }
        return false;
    }

    if (hc.CurrentTab() == HostCanvas::Tab::MemoryVisualizer)
        if (auto* mv = emu_.TryGet<MemoryVisualizer>())
            if (mv->HandleInput(hwnd, msg, wp, lp)) return true;

    /* Absolute GA pointer: free host cursor mapped to guest pixels. */
    if (kind == PointerKind::Absolute && RoutePointerInput(hwnd, msg, wp, lp))
        return true;

    /* Stylus: drive the raw touch panel (the path calibration apps read below
       the mouse abstraction). Only when the stylus source is active. */
    if (stylus_active) {
        switch (msg) {
            case WM_RBUTTONDOWN: {
                SetFocus(hwnd);
                if (!framebuffer || pen_down_) return true;
                int sx, sy;
                if (!hc.HostToGuest((int)(short)LOWORD(lp), (int)(short)HIWORD(lp), sx, sy))
                    return true;
                emu_.Get<StylusAltTap>().Begin(sx, sy);
                return true;
            }
            case WM_RBUTTONUP:
                return true;
            case WM_LBUTTONDOWN: {
                SetFocus(hwnd);
                if (!framebuffer || emu_.Get<StylusAltTap>().Running()) return true;
                int sx, sy;
                if (!hc.HostToGuest((int)(short)LOWORD(lp), (int)(short)HIWORD(lp), sx, sy))
                    return true;
                pen_down_ = true;
                SetCapture(hwnd);
                if (auto* t = emu_.TryGet<TouchInput>()) t->OnPenDown(sx, sy);
                return true;
            }
            case WM_MOUSEMOVE: {
                if (!pen_down_) return true;
                int sx, sy;
                hc.HostToGuest((int)(short)LOWORD(lp), (int)(short)HIWORD(lp), sx, sy);
                hc.ClampGuest(sx, sy);
                if (auto* t = emu_.TryGet<TouchInput>()) t->OnPenMove(sx, sy);
                return true;
            }
            case WM_LBUTTONUP: {
                if (!pen_down_) return true;
                pen_down_ = false;
                ReleaseCapture();
                int sx, sy;
                hc.HostToGuest((int)(short)LOWORD(lp), (int)(short)HIWORD(lp), sx, sy);
                hc.ClampGuest(sx, sy);
                if (auto* t = emu_.TryGet<TouchInput>()) t->OnPenUp(sx, sy);
                return true;
            }
            case WM_CAPTURECHANGED: {
                if (pen_down_) {
                    pen_down_ = false;
                    if (auto* t = emu_.TryGet<TouchInput>()) t->OnCaptureLost();
                }
                return true;
            }
        }
    }

    switch (msg) {
        case WM_KEYDOWN:
        case WM_KEYUP:
            if (framebuffer)
                emu_.Get<KeyboardRouter>().OnHostKey(static_cast<uint8_t>(wp), msg == WM_KEYUP);
            return true;
        default:
            return false;
    }
}
