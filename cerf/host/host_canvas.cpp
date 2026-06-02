#define NOMINMAX

#include "host_canvas.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "frame_renderer.h"
#include "keyboard_input.h"
#include "lcd_scan_tick.h"
#include "memory_visualizer.h"
#include "touch_input.h"
#include "uart_screen.h"

#include <algorithm>
#include <cstring>

REGISTER_SERVICE(HostCanvas);

namespace {
constexpr wchar_t  kCanvasClass[]    = L"CerfHostCanvas";
constexpr UINT_PTR kPresentTimerId   = 1;
constexpr UINT     kPresentIntervalMs = 16;  /* ~60 Hz */
constexpr int      kScrollLineStep   = 16;
}  /* namespace */

HostCanvas::~HostCanvas() = default;

void HostCanvas::OnReady() {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = &HostCanvas::WndProcStatic;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = kCanvasClass;
    if (RegisterClassExW(&wc) == 0) {
        const DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            LOG(Caution, "HostCanvas: RegisterClassExW failed (gle=%lu)\n", err);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }
}

void HostCanvas::CreateOn(HWND parent, const RECT& rect,
                          uint32_t surf_w, uint32_t surf_h) {
    parent_ = parent;
    const int w = rect.right - rect.left;
    const int h = rect.bottom - rect.top;

    hwnd_ = CreateWindowExW(0, kCanvasClass, L"",
                            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                            rect.left, rect.top, w, h,
                            parent, nullptr, GetModuleHandleW(nullptr), this);
    if (!hwnd_) {
        LOG(Caution, "HostCanvas: CreateWindowExW failed (gle=%lu)\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    RebuildPresentDib(w, h);
    RebuildGuestDib(surf_w, surf_h);
    UpdateScrollbars();
    TickAndPresent();
    timer_id_ = SetTimer(hwnd_, kPresentTimerId, kPresentIntervalMs, nullptr);
    SetFocus(hwnd_);
}

void HostCanvas::Reposition(const RECT& r) {
    if (hwnd_) MoveWindow(hwnd_, r.left, r.top,
                          r.right - r.left, r.bottom - r.top, TRUE);
}

void HostCanvas::RebuildPresentDib(int w, int h) {
    if (w < 1) w = 1;
    if (h < 1) h = 1;

    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize        = sizeof(bmi.bmiHeader);
    bmi.bmiHeader.biWidth       = w;
    bmi.bmiHeader.biHeight      = -h;            /* top-down */
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    HDC screen = GetDC(hwnd_);
    void* bits = nullptr;
    HBITMAP nd = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(hwnd_, screen);
    if (!nd || !bits) {
        LOG(Caution, "HostCanvas::RebuildPresentDib %dx%d failed (gle=%lu)\n",
            w, h, GetLastError());
        if (nd) DeleteObject(nd);
        return;
    }
    if (!present_dc_) present_dc_ = CreateCompatibleDC(nullptr);
    SelectObject(present_dc_, nd);
    if (present_dib_) DeleteObject(present_dib_);
    present_dib_  = nd;
    present_bits_ = static_cast<uint32_t*>(bits);
    canvas_w_ = w;
    canvas_h_ = h;
}

void HostCanvas::RebuildGuestDib(uint32_t w, uint32_t h) {
    if (w == 0) w = 1;
    if (h == 0) h = 1;

    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize        = sizeof(bmi.bmiHeader);
    bmi.bmiHeader.biWidth       = (LONG)w;
    bmi.bmiHeader.biHeight      = -(LONG)h;
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    HDC screen = GetDC(hwnd_);
    void* bits = nullptr;
    HBITMAP nd = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(hwnd_, screen);
    if (!nd || !bits) {
        LOG(Caution, "HostCanvas::RebuildGuestDib %ux%u failed (gle=%lu)\n",
            w, h, GetLastError());
        if (nd) DeleteObject(nd);
        return;
    }
    if (!guest_dc_) guest_dc_ = CreateCompatibleDC(nullptr);
    SelectObject(guest_dc_, nd);
    if (guest_dib_) DeleteObject(guest_dib_);
    guest_dib_  = nd;
    guest_bits_ = static_cast<uint32_t*>(bits);
    surface_w_.store(w, std::memory_order_release);
    surface_h_.store(h, std::memory_order_release);
}

void HostCanvas::SetGuestSurfaceSize(uint32_t w, uint32_t h) {
    if (w == surface_w_.load(std::memory_order_acquire) &&
        h == surface_h_.load(std::memory_order_acquire)) return;
    RebuildGuestDib(w, h);
    scroll_x_ = scroll_y_ = 0;
    UpdateScrollbars();
    if (hwnd_) InvalidateRect(hwnd_, nullptr, FALSE);
}

void HostCanvas::SetTab(Tab t, bool user_initiated) {
    if (user_initiated) user_picked_view_ = true;
    if (tab_ == t) return;
    if (tab_ == Tab::Framebuffer) ReleasePenIfDown();
    else if (tab_ == Tab::MemoryVisualizer) {
        if (GetCapture() == hwnd_) ReleaseCapture();
        if (auto* mv = emu_.TryGet<MemoryVisualizer>()) mv->CancelInput();
    }
    tab_ = t;
    UpdateScrollbars();
    if (hwnd_) InvalidateRect(hwnd_, nullptr, FALSE);
}

void HostCanvas::SetViewportMode(ViewportMode m) {
    if (mode_ == m) return;
    mode_ = m;
    scroll_x_ = scroll_y_ = 0;
    UpdateScrollbars();
    if (hwnd_) InvalidateRect(hwnd_, nullptr, FALSE);
}

void HostCanvas::SetAntialias(bool on) {
    if (antialias_ == on) return;
    antialias_ = on;
    if (hwnd_) InvalidateRect(hwnd_, nullptr, FALSE);
}

bool HostCanvas::CaptureGuestSurface(std::vector<uint32_t>& out,
                                     uint32_t& w, uint32_t& h) {
    auto* fr = emu_.TryGet<FrameRenderer>();
    if (!fr || !fr->HasFrame()) return false;
    const uint32_t sw = surface_w_.load(std::memory_order_acquire);
    const uint32_t sh = surface_h_.load(std::memory_order_acquire);
    if (sw == 0 || sh == 0 || !guest_bits_) return false;
    fr->RenderInto(guest_bits_, sw, sh);
    out.assign(guest_bits_, guest_bits_ + (size_t)sw * sh);
    w = sw;
    h = sh;
    return true;
}

HostCanvas::Layout HostCanvas::ComputeLayout() const {
    Layout L = {};
    const int cw = canvas_w_;
    const int ch = canvas_h_;
    const int sw = (int)surface_w_.load(std::memory_order_acquire);
    const int sh = (int)surface_h_.load(std::memory_order_acquire);
    if (sw <= 0 || sh <= 0 || cw <= 0 || ch <= 0) return L;

    if (mode_ == ViewportMode::Stretch) {
        L.stretch = true;
        L.dst_x = 0; L.dst_y = 0; L.dst_w = cw; L.dst_h = ch;
        L.src_x = 0; L.src_y = 0; L.src_w = sw; L.src_h = sh;
        return L;
    }
    if (mode_ == ViewportMode::Aspect) {
        const double scale = std::min((double)cw / sw, (double)ch / sh);
        int fw = (int)(sw * scale + 0.5);
        int fh = (int)(sh * scale + 0.5);
        if (fw < 1) fw = 1;
        if (fh < 1) fh = 1;
        L.stretch = true;
        L.dst_x = (cw - fw) / 2; L.dst_y = (ch - fh) / 2;
        L.dst_w = fw;            L.dst_h = fh;
        L.src_x = 0; L.src_y = 0; L.src_w = sw; L.src_h = sh;
        return L;
    }

    /* Original: 1:1, centered when it fits, scrolled when it overflows. */
    L.stretch = false;
    if (sw > cw) {
        int sx = scroll_x_;
        sx = std::clamp(sx, 0, sw - cw);
        L.src_x = sx; L.src_w = cw; L.dst_x = 0; L.dst_w = cw;
    } else {
        L.src_x = 0; L.src_w = sw; L.dst_x = (cw - sw) / 2; L.dst_w = sw;
    }
    if (sh > ch) {
        int sy = scroll_y_;
        sy = std::clamp(sy, 0, sh - ch);
        L.src_y = sy; L.src_h = ch; L.dst_y = 0; L.dst_h = ch;
    } else {
        L.src_y = 0; L.src_h = sh; L.dst_y = (ch - sh) / 2; L.dst_h = sh;
    }
    return L;
}

bool HostCanvas::HostToGuest(int cx, int cy, int& sx, int& sy) const {
    const Layout L = ComputeLayout();
    if (L.dst_w <= 0 || L.dst_h <= 0) { sx = sy = 0; return false; }
    if (L.stretch) {
        sx = L.src_x + (int)((long long)(cx - L.dst_x) * L.src_w / L.dst_w);
        sy = L.src_y + (int)((long long)(cy - L.dst_y) * L.src_h / L.dst_h);
    } else {
        sx = L.src_x + (cx - L.dst_x);
        sy = L.src_y + (cy - L.dst_y);
    }
    return cx >= L.dst_x && cx < L.dst_x + L.dst_w &&
           cy >= L.dst_y && cy < L.dst_y + L.dst_h;
}

void HostCanvas::ClampGuest(int& sx, int& sy) const {
    const int sw = (int)surface_w_.load(std::memory_order_acquire);
    const int sh = (int)surface_h_.load(std::memory_order_acquire);
    sx = std::clamp(sx, 0, (sw > 0 ? sw - 1 : 0));
    sy = std::clamp(sy, 0, (sh > 0 ? sh - 1 : 0));
}

void HostCanvas::ReleasePenIfDown() {
    if (!pen_down_) return;
    pen_down_ = false;
    if (GetCapture() == hwnd_) ReleaseCapture();
    if (auto* t = emu_.TryGet<TouchInput>()) t->OnCaptureLost();
}

void HostCanvas::UpdateScrollbars() {
    if (!hwnd_) return;
    const int sw = (int)surface_w_.load(std::memory_order_acquire);
    const int sh = (int)surface_h_.load(std::memory_order_acquire);
    const bool original = (tab_ == Tab::Framebuffer &&
                           mode_ == ViewportMode::Original);
    const bool want_h = original && sw > canvas_w_;
    const bool want_v = original && sh > canvas_h_;

    if (want_h != hsb_shown_) { ShowScrollBar(hwnd_, SB_HORZ, want_h); hsb_shown_ = want_h; }
    if (want_v != vsb_shown_) { ShowScrollBar(hwnd_, SB_VERT, want_v); vsb_shown_ = want_v; }

    if (want_h) {
        scroll_x_ = std::clamp(scroll_x_, 0, sw - canvas_w_);
        SCROLLINFO si = { sizeof(si) };
        si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
        si.nMin = 0; si.nMax = sw - 1; si.nPage = (UINT)canvas_w_; si.nPos = scroll_x_;
        SetScrollInfo(hwnd_, SB_HORZ, &si, TRUE);
    } else {
        scroll_x_ = 0;
    }
    if (want_v) {
        scroll_y_ = std::clamp(scroll_y_, 0, sh - canvas_h_);
        SCROLLINFO si = { sizeof(si) };
        si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
        si.nMin = 0; si.nMax = sh - 1; si.nPage = (UINT)canvas_h_; si.nPos = scroll_y_;
        SetScrollInfo(hwnd_, SB_VERT, &si, TRUE);
    } else {
        scroll_y_ = 0;
    }
}

void HostCanvas::TickAndPresent() {
    if (auto* tick = emu_.TryGet<LcdScanTick>()) tick->OnHostTick();

    auto* fr = emu_.TryGet<FrameRenderer>();
    const bool has_frame = fr && fr->HasFrame();
    if (has_frame && !latched_once_) {
        latched_once_ = true;
        if (!user_picked_view_) {
            tab_ = Tab::Framebuffer;
            UpdateScrollbars();
        }
    }

    if (!present_bits_) return;

    if (tab_ == Tab::Framebuffer) {
        if (has_frame && fr && guest_bits_) {
            fr->RenderInto(guest_bits_,
                           surface_w_.load(std::memory_order_acquire),
                           surface_h_.load(std::memory_order_acquire));
            ComposeFramebuffer();
        } else {
            std::memset(present_bits_, 0, (size_t)canvas_w_ * canvas_h_ * 4u);
        }
    } else if (tab_ == Tab::MemoryVisualizer) {
        if (auto* mv = emu_.TryGet<MemoryVisualizer>())
            mv->RenderInto(present_dc_, present_bits_,
                           (uint32_t)canvas_w_, (uint32_t)canvas_h_);
    } else {
        emu_.Get<UartScreen>().RenderInto(present_dc_, present_bits_,
                                          (uint32_t)canvas_w_, (uint32_t)canvas_h_);
    }
}

void HostCanvas::ComposeFramebuffer() {
    std::memset(present_bits_, 0, (size_t)canvas_w_ * canvas_h_ * 4u);
    const Layout L = ComputeLayout();
    if (L.dst_w <= 0 || L.dst_h <= 0) return;
    if (L.stretch) {
        SetStretchBltMode(present_dc_, antialias_ ? HALFTONE : COLORONCOLOR);
        SetBrushOrgEx(present_dc_, 0, 0, nullptr);
        StretchBlt(present_dc_, L.dst_x, L.dst_y, L.dst_w, L.dst_h,
                   guest_dc_, L.src_x, L.src_y, L.src_w, L.src_h, SRCCOPY);
    } else {
        BitBlt(present_dc_, L.dst_x, L.dst_y, L.dst_w, L.dst_h,
               guest_dc_, L.src_x, L.src_y, SRCCOPY);
    }
}

LRESULT CALLBACK HostCanvas::WndProcStatic(HWND hwnd, UINT msg,
                                           WPARAM wp, LPARAM lp) {
    HostCanvas* self = nullptr;
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        self = static_cast<HostCanvas*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<HostCanvas*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    return self ? self->WndProc(hwnd, msg, wp, lp)
                : DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT HostCanvas::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    /* Dev memory-visualizer owns all mouse/key/wheel input while its tab is
       active (selected from the View menu). Absent in production. */
    if (tab_ == Tab::MemoryVisualizer)
        if (auto* mv = emu_.TryGet<MemoryVisualizer>())
            if (mv->HandleInput(hwnd, msg, wp, lp)) return 0;

    switch (msg) {
        case WM_TIMER:
            if (wp == kPresentTimerId) {
                TickAndPresent();
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            break;

        case WM_SIZE: {
            RECT rc; GetClientRect(hwnd, &rc);
            const int w = (int)rc.right, h = (int)rc.bottom;
            if (w != canvas_w_ || h != canvas_h_) RebuildPresentDib(w, h);
            UpdateScrollbars();
            return 0;
        }

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            if (present_dc_)
                BitBlt(dc, 0, 0, canvas_w_, canvas_h_, present_dc_, 0, 0, SRCCOPY);
            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_HSCROLL: {
            SCROLLINFO si = { sizeof(si) }; si.fMask = SIF_ALL;
            GetScrollInfo(hwnd, SB_HORZ, &si);
            int pos = si.nPos;
            switch (LOWORD(wp)) {
                case SB_LINELEFT:  pos -= kScrollLineStep;  break;
                case SB_LINERIGHT: pos += kScrollLineStep;  break;
                case SB_PAGELEFT:  pos -= (int)si.nPage;    break;
                case SB_PAGERIGHT: pos += (int)si.nPage;    break;
                case SB_THUMBTRACK:
                case SB_THUMBPOSITION: pos = si.nTrackPos;  break;
            }
            const int maxs = std::max(0, (int)surface_w_.load() - canvas_w_);
            scroll_x_ = std::clamp(pos, 0, maxs);
            SCROLLINFO s2 = { sizeof(s2) }; s2.fMask = SIF_POS; s2.nPos = scroll_x_;
            SetScrollInfo(hwnd, SB_HORZ, &s2, TRUE);
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        case WM_VSCROLL: {
            SCROLLINFO si = { sizeof(si) }; si.fMask = SIF_ALL;
            GetScrollInfo(hwnd, SB_VERT, &si);
            int pos = si.nPos;
            switch (LOWORD(wp)) {
                case SB_LINEUP:        pos -= kScrollLineStep; break;
                case SB_LINEDOWN:      pos += kScrollLineStep; break;
                case SB_PAGEUP:        pos -= (int)si.nPage;   break;
                case SB_PAGEDOWN:      pos += (int)si.nPage;   break;
                case SB_THUMBTRACK:
                case SB_THUMBPOSITION: pos = si.nTrackPos;     break;
            }
            const int maxs = std::max(0, (int)surface_h_.load() - canvas_h_);
            scroll_y_ = std::clamp(pos, 0, maxs);
            SCROLLINFO s2 = { sizeof(s2) }; s2.fMask = SIF_POS; s2.nPos = scroll_y_;
            SetScrollInfo(hwnd, SB_VERT, &s2, TRUE);
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }

        case WM_LBUTTONDOWN: {
            SetFocus(hwnd);
            if (tab_ != Tab::Framebuffer) return 0;
            int sx, sy;
            if (!HostToGuest((int)(short)LOWORD(lp), (int)(short)HIWORD(lp), sx, sy))
                return 0;
            pen_down_ = true;
            SetCapture(hwnd);
            if (auto* t = emu_.TryGet<TouchInput>()) t->OnPenDown(sx, sy);
            return 0;
        }
        case WM_MOUSEMOVE: {
            if (!pen_down_) return 0;
            int sx, sy;
            HostToGuest((int)(short)LOWORD(lp), (int)(short)HIWORD(lp), sx, sy);
            ClampGuest(sx, sy);
            if (auto* t = emu_.TryGet<TouchInput>()) t->OnPenMove(sx, sy);
            return 0;
        }
        case WM_LBUTTONUP: {
            if (!pen_down_) return 0;
            pen_down_ = false;
            ReleaseCapture();
            int sx, sy;
            HostToGuest((int)(short)LOWORD(lp), (int)(short)HIWORD(lp), sx, sy);
            ClampGuest(sx, sy);
            if (auto* t = emu_.TryGet<TouchInput>()) t->OnPenUp(sx, sy);
            return 0;
        }
        case WM_CAPTURECHANGED: {
            if (pen_down_) {
                pen_down_ = false;
                if (auto* t = emu_.TryGet<TouchInput>()) t->OnCaptureLost();
            }
            return 0;
        }

        case WM_KEYDOWN:
        case WM_KEYUP:
            if (tab_ == Tab::Framebuffer)
                if (auto* k = emu_.TryGet<KeyboardInput>())
                    k->OnHostKey(static_cast<uint8_t>(wp), msg == WM_KEYUP);
            return 0;

        case WM_DESTROY:
            if (timer_id_)   { KillTimer(hwnd, timer_id_); timer_id_ = 0; }
            if (present_dc_) { DeleteDC(present_dc_); present_dc_ = nullptr; }
            if (present_dib_){ DeleteObject(present_dib_); present_dib_ = nullptr; present_bits_ = nullptr; }
            if (guest_dc_)   { DeleteDC(guest_dc_); guest_dc_ = nullptr; }
            if (guest_dib_)  { DeleteObject(guest_dib_); guest_dib_ = nullptr; guest_bits_ = nullptr; }
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
