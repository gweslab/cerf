#define NOMINMAX

#include "presenter_canvas.h"

#include <mmsystem.h>

#include "../core/log.h"

namespace {
constexpr wchar_t kCanvasClass[] = L"CerfPresenterCanvas";
constexpr UINT    kPresentMsg    = WM_APP + 1;

constexpr uint32_t kPausedColorQ10 = 416;
constexpr uint32_t kPausedLumaQ10  = 250;

void DesaturateAndDim(uint32_t* px, int count) {
    for (int i = 0; i < count; ++i) {
        const uint32_t p = px[i];
        const uint32_t r = (p >> 16) & 0xFFu;
        const uint32_t g = (p >> 8)  & 0xFFu;
        const uint32_t b =  p        & 0xFFu;
        const uint32_t y = ((r * 77u + g * 150u + b * 29u) >> 8) * kPausedLumaQ10;
        px[i] = (p & 0xFF000000u) |
                (((r * kPausedColorQ10 + y) >> 10) << 16) |
                (((g * kPausedColorQ10 + y) >> 10) << 8) |
                 ((b * kPausedColorQ10 + y) >> 10);
    }
}
}  /* namespace */

PresenterCanvas::~PresenterCanvas() {
    if (timer_mm_) { timeKillEvent(timer_mm_); timer_mm_ = 0; }
    if (hwnd_) DestroyWindow(hwnd_);
}

void PresenterCanvas::CreateOn(HWND parent, const RECT& rect,
                               uint32_t surf_w, uint32_t surf_h,
                               UINT present_interval_ms) {
    present_interval_ms_ = present_interval_ms ? present_interval_ms : 16;
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = &PresenterCanvas::WndProcStatic;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = kCanvasClass;
    if (RegisterClassExW(&wc) == 0) {
        const DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            LOG(Caution, "PresenterCanvas: RegisterClassExW failed (gle=%lu)\n",
                err);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }

    const int w = rect.right - rect.left;
    const int h = rect.bottom - rect.top;
    hwnd_ = CreateWindowExW(0, kCanvasClass, L"",
                            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                            rect.left, rect.top, w, h,
                            parent, nullptr, GetModuleHandleW(nullptr), this);
    if (!hwnd_) {
        LOG(Caution, "PresenterCanvas: CreateWindowExW failed (gle=%lu)\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    RebuildPresentDib(w, h);
    presenter_.Attach(hwnd_, surf_w, surf_h);
    presenter_.OnCanvasResized(canvas_w_, canvas_h_);
    TickAndPresent();
    timer_mm_ = timeSetEvent(present_interval_ms_, 1, &PresenterCanvas::PresentTimerProc,
                             reinterpret_cast<DWORD_PTR>(this),
                             TIME_PERIODIC | TIME_CALLBACK_FUNCTION);
}

void CALLBACK PresenterCanvas::PresentTimerProc(UINT, UINT, DWORD_PTR user,
                                                DWORD_PTR, DWORD_PTR) {
    auto* self = reinterpret_cast<PresenterCanvas*>(user);
    if (self && self->hwnd_ &&
        !self->present_pending_.exchange(true, std::memory_order_acq_rel))
        PostMessageW(self->hwnd_, kPresentMsg, 0, 0);
}

void PresenterCanvas::Reposition(const RECT& r) {
    if (hwnd_) MoveWindow(hwnd_, r.left, r.top,
                          r.right - r.left, r.bottom - r.top, TRUE);
}

void PresenterCanvas::RebuildPresentDib(int w, int h) {
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
        LOG(Caution, "PresenterCanvas::RebuildPresentDib %dx%d failed (gle=%lu)\n",
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

void PresenterCanvas::TickAndPresent() {
    if (host_) host_->OnPresentTick();
    if (!present_bits_) return;

    const bool alt = host_ &&
        host_->RenderAltContent(present_dc_, present_bits_, canvas_w_, canvas_h_);
    if (!alt) presenter_.ComposeInto(present_dc_, present_bits_);

    if (host_ && host_->ShouldDesaturatePresent())
        DesaturateAndDim(present_bits_, canvas_w_ * canvas_h_);
    if (host_) host_->RenderOverlay(present_dc_, canvas_w_, canvas_h_);
}

LRESULT CALLBACK PresenterCanvas::WndProcStatic(HWND hwnd, UINT msg,
                                                WPARAM wp, LPARAM lp) {
    PresenterCanvas* self = nullptr;
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        self = static_cast<PresenterCanvas*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<PresenterCanvas*>(
                   GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    return self ? self->WndProc(hwnd, msg, wp, lp)
                : DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT PresenterCanvas::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    LRESULT out;
    if (host_ && host_->HandleInput(hwnd, msg, wp, lp, out)) return out;

    switch (msg) {
        case kPresentMsg:
            present_pending_.store(false, std::memory_order_release);
            /* WM_PAINT is delivered only when the queue holds no other messages,
               input included: MSDN "About Messages and Message Queues" > Queued
               Messages (learn.microsoft.com/windows/win32/winmsg/about-messages-and-message-queues). */
            if (hwnd_) InvalidateRect(hwnd_, nullptr, FALSE);
            return 0;

        case WM_SIZE: {
            /* canvas_w_/h_ is the reference the presenter tests for scrollbar
               visibility, so it must be scrollbar-independent: the window rect
               is stable, the client rect shrinks under a visible scrollbar and
               would let the bar latch itself on permanently. */
            RECT wr; GetWindowRect(hwnd, &wr);
            const int w = (int)(wr.right - wr.left);
            const int h = (int)(wr.bottom - wr.top);
            if (w != canvas_w_ || h != canvas_h_) RebuildPresentDib(w, h);
            presenter_.OnCanvasResized(canvas_w_, canvas_h_);
            return 0;
        }

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            TickAndPresent();
            if (present_dc_)
                BitBlt(dc, 0, 0, canvas_w_, canvas_h_, present_dc_, 0, 0, SRCCOPY);
            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_HSCROLL:
            presenter_.OnHScroll(wp);
            return 0;
        case WM_VSCROLL:
            presenter_.OnVScroll(wp);
            return 0;

        case WM_DESTROY:
            if (timer_mm_) { timeKillEvent(timer_mm_); timer_mm_ = 0; }
            presenter_.Detach();
            if (present_dc_) { DeleteDC(present_dc_); present_dc_ = nullptr; }
            if (present_dib_){ DeleteObject(present_dib_); present_dib_ = nullptr; present_bits_ = nullptr; }
            hwnd_ = nullptr;
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
