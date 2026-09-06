#define NOMINMAX

#include "host_window.h"

#include <string>

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../jit/jit_runner.h"
#include "../peripherals/cerf_virt/cerf_virt_framebuffer.h"
#include "../state/shutdown_action.h"
#include "../state/shutdown_dialog.h"
#include "host_auto_resize.h"
#include "frame_renderer.h"
#include "host_canvas.h"
#include "host_dark_mode.h"
#include "host_dpi.h"
#include "host_input_capture.h"
#include "host_menu.h"
#include "host_status_bar.h"
#include "host_widget_registry.h"
#include "initial_window_size.h"
#include "window_title.h"

REGISTER_SERVICE(HostWindow);

namespace {

constexpr wchar_t  kWindowClass[]  = L"CerfHostWindow";
constexpr UINT     kLcdResizeMsg   = WM_APP + 1;
constexpr UINT     kGuestRemodeMsg = WM_APP + 2;
constexpr UINT     kShowTabMsg     = WM_APP + 3;   /* wParam = HostCanvas::Tab, lParam = rearm */
constexpr UINT     kRunJobMsg      = WM_APP + 4;   /* lParam = heap std::function */
constexpr UINT     kShutdownMsg    = WM_APP + 5;   /* posted from WM_CLOSE */
constexpr UINT_PTR kResizeDebounceTimer = 1;
constexpr UINT     kResizeDebounceMs    = 200;
constexpr UINT_PTR kCloseWatchdogTimer  = 2;
constexpr UINT     kClosePollMs         = 100;
constexpr ULONGLONG kCloseGraceMs       = 5000;

}  /* namespace */

HostWindow::~HostWindow() {
    StopUiThread();
}

void HostWindow::OnShutdown() {
    /* Stop the UI thread here, while CerfVirtFramebufferMem / FrameRenderer /
       HostCanvas are still alive: the present timer calls FrameRenderer::
       RenderInto on the UI thread, which reads those buffers. Joining only in
       the destructor lets the thread present a freed framebuffer first. */
    StopUiThread();
}

void HostWindow::StopUiThread() {
    if (ui_thread_.joinable()) {
        if (hwnd_) PostMessageW(hwnd_, WM_CLOSE, 0, 0);
        ui_thread_.join();
    }
}

void HostWindow::OnReady() {
    const auto size = emu_.Get<InitialWindowSize>().Resolve();
    initial_surface_w_ = size.width;
    initial_surface_h_ = size.height;
    LOG(Lcd, "HostWindow OnReady: opening at %ux%u\n", size.width, size.height);

    /* Per-Monitor-v2 DPI awareness comes from cerf.manifest: ConfigLoader reads
       host screen metrics for the adopt-resolution path before this window
       exists, and that read must already see physical (un-virtualized) pixels. */

    ui_thread_ = std::thread([this] { UiThreadMain(); });

    std::unique_lock<std::mutex> lk(ui_ready_mutex_);
    ui_ready_cv_.wait(lk, [&] { return ui_ready_.load(); });
}

void HostWindow::OnLcdEnabled() {
    if (emu_.Get<DeviceConfig>().guest_additions) {
        LOG(Lcd, "HostWindow::OnLcdEnabled: guest additions on, the panel "
            "layer does not size the host surface\n");
        return;
    }

    if (hwnd_) PostMessageW(hwnd_, kLcdResizeMsg, 0, 0);
}

void HostWindow::NotifyGuestRemoded(uint32_t guest_w, uint32_t guest_h) {
    if (hwnd_)
        PostMessageW(hwnd_, kGuestRemodeMsg, (WPARAM)guest_w, (LPARAM)guest_h);
}

void HostWindow::SetGuestResolution(uint32_t w, uint32_t h) {
    if (w == 0 || h == 0) return;
    emu_.Get<CerfVirtFramebuffer>().ApplyGuestMode(w, h);
    emu_.Get<HostCanvas>().SetGuestSurfaceSize(w, h);
}

void HostWindow::FitToResolution(uint32_t sw, uint32_t sh) {
    if (!hwnd_ || sw == 0 || sh == 0) return;
    if (IsZoomed(hwnd_)) return;   /* maximized: keep window, canvas adapts */
    FitWindowToSurface(sw, sh);
}

void HostWindow::ShowHwScreenTab(bool rearm_framebuffer) {
    if (hwnd_)
        PostMessageW(hwnd_, kShowTabMsg, (WPARAM)HostCanvas::Tab::Hw,
                     rearm_framebuffer ? 1 : 0);
}

void HostWindow::ShowStartupTab(bool rearm_framebuffer) {
    if (hwnd_)
        PostMessageW(hwnd_, kShowTabMsg, (WPARAM)emu_.Get<DeviceConfig>().start_tab,
                     rearm_framebuffer ? 1 : 0);
}

void HostWindow::RunOnUiThread(std::function<void()> job) {
    if (!job || !hwnd_) return;
    auto* heap = new std::function<void()>(std::move(job));
    if (!PostMessageW(hwnd_, kRunJobMsg, 0, reinterpret_cast<LPARAM>(heap)))
        delete heap;
}

void HostWindow::MatchGuestSize() {
    follow_guest_ = true;
    AutoResizeToGuest();
}

void HostWindow::WindowChromeExtent(UINT dpi, int& extra_w, int& extra_h) const {
    const DWORD style = (DWORD)GetWindowLongW(hwnd_, GWL_STYLE);
    const DWORD ex    = (DWORD)GetWindowLongW(hwnd_, GWL_EXSTYLE);
    RECT r = { 0, 0, 0, 0 };
    emu_.Get<HostDpi>().AdjustForDpi(r, style, /*bMenu=*/TRUE, ex, dpi);
    extra_w = (int)(r.right - r.left);                 /* left/top are <= 0 */
    extra_h = (int)(r.bottom - r.top)
            + (int)emu_.Get<HostStatusBar>().Height();
}

void HostWindow::AdoptResolutionToWindowMonitor() {
    if (!hwnd_) return;
    auto& dc = emu_.Get<DeviceConfig>();
    if (!dc.guest_additions ||
        !dc.adopt_guest_additions_resolution_for_host_screen)
        return;

    MONITORINFO mi = { sizeof(mi) };
    if (!GetMonitorInfoW(MonitorFromWindow(hwnd_, MONITOR_DEFAULTTONEAREST), &mi))
        return;
    const int work_w = (int)(mi.rcWork.right  - mi.rcWork.left);
    const int work_h = (int)(mi.rcWork.bottom - mi.rcWork.top);

    int ex_w = 0, ex_h = 0;
    WindowChromeExtent(emu_.Get<HostDpi>().ForWindow(hwnd_), ex_w, ex_h);
    const int surf_w = work_w - ex_w;
    const int surf_h = work_h - ex_h;
    if (surf_w < 1 || surf_h < 1) return;

    emu_.Get<CerfVirtFramebuffer>().ApplyGuestMode((uint32_t)surf_w,
                                                   (uint32_t)surf_h);
    initial_surface_w_ = (uint32_t)surf_w;
    initial_surface_h_ = (uint32_t)surf_h;
    LOG(Lcd, "HostWindow: adopt fit monitor work=%dx%d -> guest surface %dx%d\n",
        work_w, work_h, surf_w, surf_h);
}

void HostWindow::FitWindowToSurface(uint32_t sw, uint32_t sh) {
    if (!hwnd_ || sw == 0 || sh == 0 || fullscreen_.IsActive()) return;

    int ex_w = 0, ex_h = 0;
    WindowChromeExtent(emu_.Get<HostDpi>().ForWindow(hwnd_), ex_w, ex_h);
    int outer_w = (int)sw + ex_w;
    int outer_h = (int)sh + ex_h;

    int x = 0, y = 0;
    bool move = false;
    MONITORINFO mi = { sizeof(mi) };
    if (GetMonitorInfoW(MonitorFromWindow(hwnd_, MONITOR_DEFAULTTONEAREST), &mi)) {
        const RECT wa = mi.rcWork;
        const int wa_w = (int)(wa.right - wa.left);
        const int wa_h = (int)(wa.bottom - wa.top);
        if (outer_w > wa_w) outer_w = wa_w;
        if (outer_h > wa_h) outer_h = wa_h;

        x = (int)wa.left + (wa_w - outer_w) / 2;
        y = (int)wa.top  + (wa_h - outer_h) / 2;
        move = true;
    }

    if (IsZoomed(hwnd_)) ShowWindow(hwnd_, SW_RESTORE);
    SetWindowPos(hwnd_, nullptr, x, y, outer_w, outer_h,
                 SWP_NOZORDER | (move ? 0u : SWP_NOMOVE));
}

void HostWindow::AutoResizeToGuest() {
    auto& canvas = emu_.Get<HostCanvas>();
    const uint32_t sw = canvas.ContentWidth();
    const uint32_t sh = canvas.ContentHeight();
    if (sw == 0 || sh == 0) return;
    FitWindowToSurface(sw, sh);
    LOG(Lcd, "HostWindow: matched guest size %ux%u\n", sw, sh);
}

void HostWindow::RefitIfFollowingGuest() {
    if (follow_guest_) AutoResizeToGuest();
}

void HostWindow::RunShutdownPrompt() {
    const ShutdownChoice c = emu_.Get<ShutdownDialog>().Show();
    if (c != ShutdownChoice::Exit && c != ShutdownChoice::ExitSave)
        shutdown_pending_ = false;
    emu_.Get<ShutdownAction>().Perform(c);
}

void HostWindow::BeginShutdownTeardown() {
    if (closing_) return;
    /* Stop the CPU cooperatively first - destroying the window with the JIT
       still grinding ARM code orphans cerf.exe; the watchdog destroys it once parked. */
    closing_ = true;
    if (auto* jit = emu_.TryGet<JitRunner>()) jit->RequestStop();
    close_start_tick_ = GetTickCount64();
    SetTimer(hwnd_, kCloseWatchdogTimer, kClosePollMs, nullptr);
}

void HostWindow::UiThreadMain() {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = &HostWindow::WndProcStatic;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon         = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1));
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = kWindowClass;
    if (RegisterClassExW(&wc) == 0) {
        const DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            LOG(Caution, "HostWindow: RegisterClassExW failed (gle=%lu)\n", err);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }

    emu_.Get<HostDarkMode>().Init();  /* app dark mode before the window exists */

    const DWORD style = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
    const LONG  th    = (LONG)emu_.Get<HostStatusBar>().Height();
    RECT r = { 0, 0, (LONG)initial_surface_w_, (LONG)initial_surface_h_ + th };
    AdjustWindowRectEx(&r, style, /*bMenu=*/TRUE, 0);

    HMENU menu = emu_.Get<HostMenu>().Build();
    const std::wstring title = emu_.Get<WindowTitle>().Compose();
    hwnd_ = CreateWindowExW(0, kWindowClass, title.c_str(),
                            style, CW_USEDEFAULT, CW_USEDEFAULT,
                            r.right - r.left, r.bottom - r.top,
                            nullptr, menu, GetModuleHandleW(nullptr), this);
    if (!hwnd_) {
        LOG(Caution, "HostWindow: CreateWindowExW failed (gle=%lu)\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    emu_.Get<HostDarkMode>().ApplyToWindow(hwnd_);  /* dark title bar + theme */

    /* The window now has a monitor, so the guest surface can be fitted to it
       before the canvas is built and before the guest reads its framebuffer
       dims (no re-mode needed). No-op unless adopt-resolution is enabled. */
    AdoptResolutionToWindowMonitor();

    /* Must run before the canvas is built - the canvas takes the window
       client size, and an unclamped oversized surface would size it
       off-screen with no scrollbars engaged. */
    FitWindowToSurface(initial_surface_w_, initial_surface_h_);

    RECT rc;
    GetClientRect(hwnd_, &rc);
    const LONG sbh = (LONG)emu_.Get<HostStatusBar>().Height();
    RECT cv = { 0, 0, rc.right, rc.bottom - sbh };
    auto& canvas = emu_.Get<HostCanvas>();
    canvas.CreateOn(hwnd_, cv, initial_surface_w_, initial_surface_h_);
    RECT sb = { 0, rc.bottom - sbh, rc.right, rc.bottom };
    emu_.Get<HostStatusBar>().CreateOn(hwnd_, sb);
    emu_.Get<HostDarkMode>().ApplyToWindow(canvas.Hwnd());
    emu_.Get<HostInputCapture>().AttachUiThread(hwnd_);

    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);

    {
        std::lock_guard<std::mutex> lk(ui_ready_mutex_);
        ui_ready_.store(true);
    }
    ui_ready_cv_.notify_all();

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    LOG(Lcd, "HostWindow UI thread exiting\n");
}

LRESULT CALLBACK HostWindow::WndProcStatic(HWND hwnd, UINT msg,
                                           WPARAM wp, LPARAM lp) {
    HostWindow* self = nullptr;
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        self = static_cast<HostWindow*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<HostWindow*>(
                   GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    return self ? self->WndProc(hwnd, msg, wp, lp)
                : DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT HostWindow::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    LRESULT dark_out = 0;
    if (emu_.Get<HostDarkMode>().HandleMessage(hwnd, msg, wp, lp, dark_out))
        return dark_out;

    if (msg == kLcdResizeMsg) {
        uint32_t w = 0, h = 0;
        if (auto* fr = emu_.TryGet<FrameRenderer>()) fr->PresentedSize(w, h);
        LOG(Lcd, "HostWindow: LCD resize, presented %ux%u\n", w, h);
        if (w != 0 && h != 0) {
            emu_.Get<HostCanvas>().SetGuestSurfaceSize(w, h);
            if (follow_guest_) AutoResizeToGuest();
        }
        return 0;
    }

    if (msg == kShowTabMsg) {
        auto& canvas = emu_.Get<HostCanvas>();
        canvas.SetTab((HostCanvas::Tab)wp, /*user_initiated=*/false);
        if (lp) canvas.RearmFramebufferAutoSwitch();
        return 0;
    }

    if (msg == kRunJobMsg) {
        auto* heap = reinterpret_cast<std::function<void()>*>(lp);
        (*heap)();
        delete heap;
        return 0;
    }

    if (msg == kShutdownMsg) {
        RunShutdownPrompt();
        return 0;
    }

    if (msg == kGuestRemodeMsg) {
        SetGuestResolution((uint32_t)wp, (uint32_t)lp);
        return 0;
    }

    switch (msg) {
        case WM_SIZE: {
            RECT rc;
            GetClientRect(hwnd, &rc);
            const bool fs = fullscreen_.IsActive();   /* status bar gone in fullscreen */
            const LONG sbh = fs ? 0 : (LONG)emu_.Get<HostStatusBar>().Height();
            RECT cv = { 0, 0, rc.right, rc.bottom - sbh };
            emu_.Get<HostCanvas>().Reposition(cv);
            if (user_resizing_ && wp != SIZE_MINIMIZED) user_resized_ = true;
            ShowWindow(emu_.Get<HostStatusBar>().Hwnd(), fs ? SW_HIDE : SW_SHOW);
            if (!fs) {
                RECT sb = { 0, rc.bottom - sbh, rc.right, rc.bottom };
                emu_.Get<HostStatusBar>().Reposition(sb);
            }
            /* Coalesce the WM_SIZE storm: one re-mode per intermediate size
               floods gwes with PDEV re-enables and crashes at high resolution. */
            if (auto* ar = emu_.TryGet<HostAutoResize>();
                wp != SIZE_MINIMIZED && ar && ar->Enabled())
                SetTimer(hwnd, kResizeDebounceTimer, kResizeDebounceMs, nullptr);
            return 0;
        }

        /* Dirty the follow-guest bit only on genuine user action - drag-
           resize (bracketed by ENTER/EXITSIZEMOVE) and maximize. Raw
           WM_SIZE also fires for the first show and our own programmatic
           AutoResizeToGuest, which must NOT count as the user taking over. */
        case WM_ENTERSIZEMOVE:
            user_resizing_ = true;
            user_resized_  = false;
            return 0;
        case WM_EXITSIZEMOVE:
            if (user_resizing_) {
                user_resizing_ = false;
                if (user_resized_) follow_guest_ = false;
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wp & 0xFFF0) == (WPARAM)SC_MAXIMIZE) follow_guest_ = false;
            break;

        case WM_ACTIVATE:
            if (LOWORD(wp) == WA_INACTIVE)
                if (auto* cap = emu_.TryGet<HostInputCapture>()) cap->OnFocusLost();
            break;

        case WM_TIMER:
            if (wp == kCloseWatchdogTimer) {
                auto* jit = emu_.TryGet<JitRunner>();
                if (!jit || jit->Stopped()) {
                    KillTimer(hwnd, kCloseWatchdogTimer);
                    DestroyWindow(hwnd);
                } else if (GetTickCount64() - close_start_tick_ >= kCloseGraceMs) {
                    /* The JIT thread didn't observe the cooperative stop within
                       the grace period - wedged in a guest spin or host wait, it
                       will never exit on its own. Force the process down so
                       cerf.exe doesn't survive with a running JIT thread. */
                    LOG(Caution, "HostWindow: JIT did not stop within %llums of "
                        "close; forcing process exit\n",
                        (unsigned long long)kCloseGraceMs);
                    KillTimer(hwnd, kCloseWatchdogTimer);
                    Log::Close();
                    TerminateProcess(GetCurrentProcess(),
                                     CERF_FATAL_RUNTIME_ERROR);
                }
                return 0;
            }
            if (wp == kResizeDebounceTimer) {
                KillTimer(hwnd, kResizeDebounceTimer);
                if (auto* ar = emu_.TryGet<HostAutoResize>()) {
                    RECT rc;
                    GetClientRect(hwnd, &rc);
                    const LONG sbh = fullscreen_.IsActive() ? 0 : (LONG)emu_.Get<HostStatusBar>().Height();
                    ar->OnUserResizeEnd((uint32_t)rc.right,
                                        (uint32_t)(rc.bottom - sbh));
                }
                return 0;
            }
            break;

        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
            mmi->ptMinTrackSize.x = 200;
            mmi->ptMinTrackSize.y = 150;
            return 0;
        }

        case WM_INITMENUPOPUP:
            emu_.Get<HostMenu>().OnInitMenuPopup((HMENU)wp);
            return 0;

        case WM_COMMAND:
            if (HIWORD(wp) == 0) {  /* menu item */
                const int id = LOWORD(wp);
                auto& reg = emu_.Get<HostWidgetRegistry>();
                if (reg.OwnsCommand(id)) reg.Dispatch(id);
                else                     emu_.Get<HostMenu>().HandleCommand(id);
                return 0;
            }
            break;

        case WM_CLOSE:
            /* Never block/pump in the window proc: post and return so the UI
               loop keeps running; prompt + async save run from kShutdownMsg. */
            if (!closing_ && !shutdown_pending_) {
                shutdown_pending_ = true;
                PostMessageW(hwnd, kShutdownMsg, 0, 0);
            }
            return 0;

        case WM_DESTROY:
            emu_.Get<HostInputCapture>().DetachUiThread();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
