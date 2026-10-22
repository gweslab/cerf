#define NOMINMAX

#include "host_window.h"

#include <string>

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/log.h>
#include <cerfcore/platform/wide_text_win32.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_framebuffer.h>
#include <cerffrontend/shutdown_prompt.h>
#include <cerffrontend/shutdown_teardown.h>
#include "shutdown_dialog.h"
#include <cerffrontend/guest_auto_resize.h>
#include <cerffrontend/startup_scale.h>
#include <cerfcore/host/frame_renderer.h>
#include "host_canvas.h"
#include "host_dark_mode.h"
#include "host_dpi.h"
#include "host_focus_policy.h"
#include "host_input_capture.h"
#include "host_menu.h"
#include "host_status_bar.h"
#include "host_window_geometry.h"
#include <cerffrontend/window_title.h>

REGISTER_SERVICE_AS(HostWindow, cerffrontend::FrontendWindow);

namespace {

constexpr wchar_t  kWindowClass[]  = L"CerfHostWindow";
constexpr UINT     kLcdResizeMsg   = WM_APP + 1;
constexpr UINT     kGuestRemodeMsg = WM_APP + 2;
constexpr UINT     kRunJobMsg      = WM_APP + 4;   /* lParam = heap std::function */
constexpr UINT     kShutdownMsg    = WM_APP + 5;   /* posted from WM_CLOSE */
constexpr UINT_PTR kResizeDebounceTimer = 1;
constexpr UINT_PTR kCloseWatchdogTimer  = 2;

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
    const auto& dc = emu_.Get<cerfcore::DeviceConfig>();
    initial_surface_w_ = dc.board_configurable_screen_width;
    initial_surface_h_ = dc.board_configurable_screen_height;
    LOG(Lcd, "HostWindow OnReady: opening at %ux%u\n", initial_surface_w_,
        initial_surface_h_);

    /* Per-Monitor-v2 DPI awareness comes from cerf.manifest: ConfigLoader reads
       host screen metrics for the adopt-resolution path before this window
       exists, and that read must already see physical (un-virtualized) pixels. */

    ui_thread_ = std::thread([this] { UiThreadMain(); });

    std::unique_lock<std::mutex> lk(ui_ready_mutex_);
    ui_ready_cv_.wait(lk, [&] { return ui_ready_.load(); });
    lk.unlock();
}

void HostWindow::OnLcdEnabled() {
    if (hwnd_) PostMessageW(hwnd_, kLcdResizeMsg, 0, 0);
}

uint32_t HostWindow::GuestSurfaceWidth() const {
    return emu_.Get<HostCanvas>().GuestSurfaceWidth();
}

uint32_t HostWindow::GuestSurfaceHeight() const {
    return emu_.Get<HostCanvas>().GuestSurfaceHeight();
}

void HostWindow::SetGuestSurfaceSize(uint32_t w, uint32_t h) {
    emu_.Get<HostCanvas>().SetGuestSurfaceSize(w, h);
}

void HostWindow::NotifyGuestRemoded(uint32_t guest_w, uint32_t guest_h) {
    if (hwnd_)
        PostMessageW(hwnd_, kGuestRemodeMsg, (WPARAM)guest_w, (LPARAM)guest_h);
}

void HostWindow::SetGuestResolution(uint32_t w, uint32_t h) {
    if (w == 0 || h == 0) return;
    emu_.Get<cerfcore::CerfVirtFramebuffer>().ApplyGuestMode(w, h);
    emu_.Get<HostCanvas>().SetGuestSurfaceSize(w, h);
}

void HostWindow::FitToResolution(uint32_t sw, uint32_t sh) {
    if (!hwnd_ || sw == 0 || sh == 0) return;
    if (IsZoomed(hwnd_)) return;   /* maximized: keep window, canvas adapts */
    FitWindowToSurface(sw, sh);
}

void HostWindow::RunOnUiThread(std::function<void()> job) {
    if (!job || !hwnd_) return;
    auto* heap = new std::function<void()>(std::move(job));
    if (!PostMessageW(hwnd_, kRunJobMsg, 0, reinterpret_cast<LPARAM>(heap)))
        delete heap;
}

bool HostWindow::RunOnUiThreadAfter(uint32_t delay_ms, std::function<void()> job) {
    if (!job || !hwnd_) return false;
    if (std::this_thread::get_id() != ui_thread_.get_id())
        emu_.Get<cerfcore::Fatal>().Die("HostWindow::RunOnUiThreadAfter off the UI thread");
    const UINT_PTR id = next_delayed_id_;
    next_delayed_id_  = id == kDelayedJobLast ? kDelayedJobFirst : id + 1;
    if (SetTimer(hwnd_, id, delay_ms, nullptr) == 0) {
        LOG(Caution, "HostWindow: SetTimer failed (gle=%lu)\n", GetLastError());
        return false;
    }
    delayed_jobs_[id] = std::move(job);
    return true;
}

HostWindow::Tab HostWindow::CurrentTab() const { return emu_.Get<HostCanvas>().CurrentTab(); }

void HostWindow::SetTab(Tab tab, bool user_initiated) {
    emu_.Get<HostCanvas>().SetTab(tab, user_initiated);
}

cerffrontend::ViewportMode HostWindow::Mode() const { return emu_.Get<HostCanvas>().Mode(); }

int HostWindow::IntegerFactor() const { return emu_.Get<HostCanvas>().IntegerFactor(); }

bool HostWindow::Antialias() const { return emu_.Get<HostCanvas>().Antialias(); }

void HostWindow::SetViewportMode(cerffrontend::ViewportMode m) {
    emu_.Get<HostCanvas>().SetViewportMode(m);
}

void HostWindow::SetIntegerScale(int factor) { emu_.Get<HostCanvas>().SetIntegerScale(factor); }

void HostWindow::SetAntialias(bool on) { emu_.Get<HostCanvas>().SetAntialias(on); }

bool HostWindow::CaptureGuestSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) {
    return emu_.Get<HostCanvas>().CaptureGuestSurface(out, w, h);
}

void HostWindow::MatchGuestSize() {
    follow_guest_ = true;
    AutoResizeToGuest();
}

void HostWindow::FitWindowToSurface(uint32_t sw, uint32_t sh) {
    if (!hwnd_ || sw == 0 || sh == 0 || fullscreen_.IsActive()) return;
    emu_.Get<HostWindowGeometry>().FitToSurface(hwnd_, sw, sh);
}

void HostWindow::ToggleFullscreen() {
    if (hwnd_) fullscreen_.Toggle(hwnd_, emu_.Get<HostFocusPolicy>().MayActivate());
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
    emu_.Get<cerffrontend::ShutdownPrompt>().FinishCloseRequest(emu_.Get<ShutdownDialog>().Show());
}

void HostWindow::BeginShutdownTeardown() {
    if (!emu_.Get<cerffrontend::ShutdownTeardown>().Begin()) return;
    SetTimer(hwnd_, kCloseWatchdogTimer, cerffrontend::ShutdownTeardown::kPollMs, nullptr);
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
            cerfcore::CerfFatalExit(cerfcore::CERF_FATAL_RUNTIME_ERROR);
        }
    }

    emu_.Get<HostDarkMode>().Init();  /* app dark mode before the window exists */

    const DWORD style = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
    const LONG  th    = (LONG)emu_.Get<HostStatusBar>().Height();
    RECT r = { 0, 0, (LONG)initial_surface_w_, (LONG)initial_surface_h_ + th };
    AdjustWindowRectEx(&r, style, /*bMenu=*/TRUE, 0);

    HMENU menu = emu_.Get<HostMenu>().Build();
    const std::wstring title =
        cerfcore::Utf8ToWide(emu_.Get<cerffrontend::WindowTitle>().Compose().c_str());
    hwnd_ = CreateWindowExW(0, kWindowClass, title.c_str(),
                            style, CW_USEDEFAULT, CW_USEDEFAULT,
                            r.right - r.left, r.bottom - r.top,
                            nullptr, menu, GetModuleHandleW(nullptr), this);
    if (!hwnd_) {
        LOG(Caution, "HostWindow: CreateWindowExW failed (gle=%lu)\n",
            GetLastError());
        cerfcore::CerfFatalExit(cerfcore::CERF_FATAL_RUNTIME_ERROR);
    }

    emu_.Get<HostDarkMode>().ApplyToWindow(hwnd_);

    emu_.Get<HostWindowGeometry>().AdoptSurfaceForMonitor(hwnd_, initial_surface_w_,
                                                          initial_surface_h_);
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

    const int scale = emu_.Get<cerffrontend::StartupScale>().Factor(
        static_cast<int>(emu_.Get<HostDpi>().ForPrimaryMonitor()));
    if (scale > 1) {
        canvas.SetIntegerScale(scale);
        FitWindowToSurface(canvas.ContentWidth(), canvas.ContentHeight());
    }

    emu_.Get<HostFocusPolicy>().Show(hwnd_);
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
        if (auto* fr = emu_.TryGet<cerfcore::FrameRenderer>()) fr->PresentedSize(w, h);
        LOG(Lcd, "HostWindow: LCD resize, presented %ux%u\n", w, h);
        if (w != 0 && h != 0) {
            emu_.Get<HostCanvas>().SetGuestSurfaceSize(w, h);
            if (follow_guest_) AutoResizeToGuest();
        }
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
            if (auto* ar = emu_.TryGet<cerffrontend::GuestAutoResize>();
                wp != SIZE_MINIMIZED && ar && ar->Enabled())
                SetTimer(hwnd, kResizeDebounceTimer, cerffrontend::GuestAutoResize::kDebounceMs,
                         nullptr);
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

        case WM_SETFOCUS: {
            const HWND canvas = emu_.Get<HostCanvas>().Hwnd();
            LOG(Lcd, "HostWindow: keyboard focus %p -> canvas %p\n", (void*)wp,
                (void*)canvas);
            SetFocus(canvas);
            return 0;
        }

        case WM_TIMER:
            if (auto job = delayed_jobs_.find(wp); job != delayed_jobs_.end()) {
                KillTimer(hwnd, wp);
                std::function<void()> run = std::move(job->second);
                delayed_jobs_.erase(job);
                run();
                return 0;
            }
            if (wp == kCloseWatchdogTimer) {
                switch (emu_.Get<cerffrontend::ShutdownTeardown>().Poll()) {
                    case cerffrontend::ShutdownTeardown::Step::kWaiting:
                        break;
                    case cerffrontend::ShutdownTeardown::Step::kStopped:
                        KillTimer(hwnd, kCloseWatchdogTimer);
                        DestroyWindow(hwnd);
                        break;
                    case cerffrontend::ShutdownTeardown::Step::kWedged:
                        KillTimer(hwnd, kCloseWatchdogTimer);
                        cerfcore::Log::Close();
                        TerminateProcess(GetCurrentProcess(),
                                         cerfcore::CERF_FATAL_RUNTIME_ERROR);
                        break;
                }
                return 0;
            }
            if (wp == kResizeDebounceTimer) {
                KillTimer(hwnd, kResizeDebounceTimer);
                if (auto* ar = emu_.TryGet<cerffrontend::GuestAutoResize>()) {
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
                emu_.Get<HostMenu>().Dispatch(LOWORD(wp));
                return 0;
            }
            break;

        case WM_CLOSE:
            if (emu_.Get<cerffrontend::ShutdownPrompt>().BeginCloseRequest())
                PostMessageW(hwnd, kShutdownMsg, 0, 0);
            return 0;

        case WM_DESTROY:
            emu_.Get<HostInputCapture>().DetachUiThread();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
