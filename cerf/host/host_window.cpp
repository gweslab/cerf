#define NOMINMAX

#include "host_window.h"

#include <dwmapi.h>

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../jit/jit_runner.h"
#include "../peripherals/cerf_virt/cerf_virt_framebuffer.h"
#include "../version.h"
#include "frame_renderer.h"
#include "host_canvas.h"
#include "host_dark_mode.h"
#include "memory_visualizer.h"
#include "host_input_capture.h"
#include "host_screenshot.h"
#include "host_status_bar.h"
#include "host_widget_registry.h"

REGISTER_SERVICE(HostWindow);

namespace {

constexpr wchar_t  kWindowClass[]  = L"CerfHostWindow";
constexpr UINT     kLcdResizeMsg   = WM_APP + 1;

enum MenuId : int {
    kIdCtrlAltDel    = 201,
    kIdViewUart    = 100,
    kIdViewFb      = 101,
    kIdViewMemViz  = 102,
    kIdVpOriginal  = 110,
    kIdVpAspect    = 111,
    kIdVpStretch   = 112,
    kIdAliasing    = 113,
    kIdSaveShot    = 120,
    kIdCopyShot    = 121,
    kIdMatchGuest  = 122,
    kIdAbout       = 130,
};

}  /* namespace */

HostWindow::~HostWindow() {
    if (ui_thread_.joinable()) {
        if (hwnd_) PostMessageW(hwnd_, WM_CLOSE, 0, 0);
        ui_thread_.join();
    }
}

void HostWindow::OnReady() {
    auto& dc = emu_.Get<DeviceConfig>();
    uint32_t iw = dc.board_configurable_screen_width;
    uint32_t ih = dc.board_configurable_screen_height;
    initial_surface_w_ = iw;
    initial_surface_h_ = ih;
    LOG(Lcd, "HostWindow OnReady: opening at %ux%u\n", iw, ih);

    /* Pixel-exact regardless of system DPI scaling. */
    SetProcessDPIAware();

    ui_thread_ = std::thread([this] { UiThreadMain(); });

    std::unique_lock<std::mutex> lk(ui_ready_mutex_);
    ui_ready_cv_.wait(lk, [&] { return ui_ready_.load(); });
}

void HostWindow::OnLcdEnabled(uint32_t fb_w, uint32_t fb_h) {
    if (emu_.Get<DeviceConfig>().guest_additions) {
        LOG(Lcd, "HostWindow::OnLcdEnabled: guest additions on, ignoring "
            "native %ux%u\n", fb_w, fb_h);
        return;
    }
    uint32_t host_w = fb_w, host_h = fb_h;
    if (auto* fr = emu_.TryGet<FrameRenderer>()) {
        const auto [w, h] = fr->HostSizeFor(fb_w, fb_h);
        host_w = w;
        host_h = h;
    }
    LOG(Lcd, "HostWindow::OnLcdEnabled: fb=%ux%u host=%ux%u\n",
        fb_w, fb_h, host_w, host_h);
    if (hwnd_)
        PostMessageW(hwnd_, kLcdResizeMsg, (WPARAM)host_w, (LPARAM)host_h);
}

HMENU HostWindow::BuildMenu() {
    HMENU bar = CreateMenu();

    /* Filled on demand in WM_INITMENUPOPUP: the widget block (capture lock
       first) then Send Ctrl+Alt+Del. */
    HMENU actions = CreatePopupMenu();
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)actions, L"Actions");

    HMENU view = CreatePopupMenu();
    AppendMenuW(view, MF_STRING, kIdViewUart,   L"UART Screen");
    AppendMenuW(view, MF_STRING, kIdViewFb,     L"Framebuffer");
    if (emu_.TryGet<MemoryVisualizer>())
        AppendMenuW(view, MF_STRING, kIdViewMemViz, L"Memory Visualizer (dev)");
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdVpOriginal, L"Original view");
    AppendMenuW(view, MF_STRING, kIdVpAspect,   L"Resize + match aspect ratio");
    AppendMenuW(view, MF_STRING, kIdVpStretch,  L"Stretch");
    AppendMenuW(view, MF_STRING, kIdAliasing,   L"Apply aliasing");
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdSaveShot,   L"Save screenshot");
    AppendMenuW(view, MF_STRING, kIdCopyShot,   L"Copy screenshot");
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdMatchGuest, L"Match guest size");
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)view, L"View");
    AppendMenuW(bar, MF_STRING, kIdAbout, L"About");
    return bar;
}

void HostWindow::SyncMenu() {
    if (!hmenu_) return;

    HMENU view = GetSubMenu(hmenu_, 1);
    if (!view) return;
    auto& canvas = emu_.Get<HostCanvas>();
    int view_id = kIdViewUart;
    switch (canvas.CurrentTab()) {
        case HostCanvas::Tab::Uart:             view_id = kIdViewUart;   break;
        case HostCanvas::Tab::Framebuffer:      view_id = kIdViewFb;     break;
        case HostCanvas::Tab::MemoryVisualizer: view_id = kIdViewMemViz; break;
    }
    CheckMenuRadioItem(view, kIdViewUart, kIdViewMemViz, view_id, MF_BYCOMMAND);
    int vp_id = kIdVpOriginal;
    switch (canvas.Mode()) {
        case HostCanvas::ViewportMode::Original: vp_id = kIdVpOriginal; break;
        case HostCanvas::ViewportMode::Aspect:   vp_id = kIdVpAspect;   break;
        case HostCanvas::ViewportMode::Stretch:  vp_id = kIdVpStretch;  break;
    }
    CheckMenuRadioItem(view, kIdVpOriginal, kIdVpStretch, vp_id, MF_BYCOMMAND);
    CheckMenuItem(view, kIdAliasing,
                  MF_BYCOMMAND | (canvas.Antialias() ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(view, kIdMatchGuest,
                  MF_BYCOMMAND | (follow_guest_ ? MF_CHECKED : MF_UNCHECKED));
}

void HostWindow::HandleCommand(int id) {
    auto& canvas = emu_.Get<HostCanvas>();
    switch (id) {
        case kIdCtrlAltDel:    emu_.Get<HostInputCapture>().SendCtrlAltDel(); break;
        case kIdViewUart:   canvas.SetTab(HostCanvas::Tab::Uart, true);        break;
        case kIdViewFb:     canvas.SetTab(HostCanvas::Tab::Framebuffer, true); break;
        case kIdViewMemViz: canvas.SetTab(HostCanvas::Tab::MemoryVisualizer, true); break;
        case kIdVpOriginal: canvas.SetViewportMode(HostCanvas::ViewportMode::Original); break;
        case kIdVpAspect:   canvas.SetViewportMode(HostCanvas::ViewportMode::Aspect);   break;
        case kIdVpStretch:  canvas.SetViewportMode(HostCanvas::ViewportMode::Stretch);  break;
        case kIdAliasing:   canvas.SetAntialias(!canvas.Antialias()); break;
        case kIdSaveShot:   emu_.Get<HostScreenshot>().Save(); break;
        case kIdCopyShot:   emu_.Get<HostScreenshot>().Copy(); break;
        case kIdMatchGuest:
            follow_guest_ = true;
            AutoResizeToGuest();
            break;
        case kIdAbout:
            MessageBoxW(hwnd_,
                L"CE Runtime Foundation v" CERF_VERSION_DISPLAY_WSTR
                L"\nhttps://github.com/gweslab/cerf",
                L"About CERF", MB_OK | MB_ICONINFORMATION);
            break;
    }
}

void HostWindow::FitWindowToSurface(uint32_t sw, uint32_t sh) {
    if (!hwnd_ || sw == 0 || sh == 0) return;

    const DWORD style = (DWORD)GetWindowLongW(hwnd_, GWL_STYLE);
    const DWORD ex    = (DWORD)GetWindowLongW(hwnd_, GWL_EXSTYLE);
    const LONG  th    = (LONG)emu_.Get<HostStatusBar>().Height();
    RECT r = { 0, 0, (LONG)sw, (LONG)sh + th };
    AdjustWindowRectEx(&r, style, /*bMenu=*/TRUE, ex);
    int outer_w = (int)(r.right - r.left);
    int outer_h = (int)(r.bottom - r.top);

    int x = 0, y = 0;
    bool move = false;
    RECT wa = {};
    if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0)) {
        const int wa_w = (int)(wa.right - wa.left);
        const int wa_h = (int)(wa.bottom - wa.top);
        if (outer_w > wa_w) outer_w = wa_w;
        if (outer_h > wa_h) outer_h = wa_h;

        /* Nudge the origin in too: a surface larger than the work area would
           otherwise grow the frame off its cascade top-left, landing the
           right/bottom edges off-screen. */
        RECT cur = {};
        GetWindowRect(hwnd_, &cur);
        x = (int)cur.left;
        y = (int)cur.top;
        if (x + outer_w > wa.right)  x = (int)wa.right  - outer_w;
        if (y + outer_h > wa.bottom) y = (int)wa.bottom - outer_h;
        if (x < (int)wa.left) x = (int)wa.left;
        if (y < (int)wa.top)  y = (int)wa.top;
        move = true;
    }

    if (IsZoomed(hwnd_)) ShowWindow(hwnd_, SW_RESTORE);
    SetWindowPos(hwnd_, nullptr, x, y, outer_w, outer_h,
                 SWP_NOZORDER | (move ? 0u : SWP_NOMOVE));
}

void HostWindow::AutoResizeToGuest() {
    auto& canvas = emu_.Get<HostCanvas>();
    const uint32_t sw = canvas.GuestSurfaceWidth();
    const uint32_t sh = canvas.GuestSurfaceHeight();
    if (sw == 0 || sh == 0) return;
    FitWindowToSurface(sw, sh);
    LOG(Lcd, "HostWindow: matched guest size %ux%u\n", sw, sh);
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

    hmenu_ = BuildMenu();
    hwnd_ = CreateWindowExW(0, kWindowClass, L"CERF " CERF_VERSION_DISPLAY_WSTR,
                            style, CW_USEDEFAULT, CW_USEDEFAULT,
                            r.right - r.left, r.bottom - r.top,
                            nullptr, hmenu_, GetModuleHandleW(nullptr), this);
    if (!hwnd_) {
        LOG(Caution, "HostWindow: CreateWindowExW failed (gle=%lu)\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    /* DO NOT drop the 19 fallback — Windows 10 1809-1909 only accept the
       predecessor attribute; 20 is 20H1+. */
    {
        const BOOL dark = TRUE;
        if (FAILED(DwmSetWindowAttribute(hwnd_, 20, &dark, sizeof(dark))))
            DwmSetWindowAttribute(hwnd_, 19, &dark, sizeof(dark));
    }
    emu_.Get<HostDarkMode>().ApplyToWindow(hwnd_);

    /* Clamp to the work area before building the canvas: the canvas takes the
       window client size, so an oversized surface then scrolls instead of
       spilling off-screen. */
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
        const uint32_t w = (uint32_t)wp;
        const uint32_t h = (uint32_t)lp;
        if (w != 0 && h != 0) {
            emu_.Get<HostCanvas>().SetGuestSurfaceSize(w, h);
            if (follow_guest_) AutoResizeToGuest();
        }
        return 0;
    }

    switch (msg) {
        case WM_SIZE: {
            RECT rc;
            GetClientRect(hwnd, &rc);
            const LONG sbh = (LONG)emu_.Get<HostStatusBar>().Height();
            RECT cv = { 0, 0, rc.right, rc.bottom - sbh };
            emu_.Get<HostCanvas>().Reposition(cv);
            RECT sb = { 0, rc.bottom - sbh, rc.right, rc.bottom };
            emu_.Get<HostStatusBar>().Reposition(sb);
            return 0;
        }

        /* Dirty the follow-guest bit only on genuine user action — drag-
           resize (bracketed by ENTER/EXITSIZEMOVE) and maximize. Raw
           WM_SIZE also fires for the first show and our own programmatic
           AutoResizeToGuest, which must NOT count as the user taking over. */
        case WM_ENTERSIZEMOVE:
            user_resizing_ = true;
            return 0;
        case WM_EXITSIZEMOVE:
            if (user_resizing_) { user_resizing_ = false; follow_guest_ = false; }
            return 0;
        case WM_SYSCOMMAND:
            if ((wp & 0xFFF0) == (WPARAM)SC_MAXIMIZE) follow_guest_ = false;
            break;

        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
            mmi->ptMinTrackSize.x = 200;
            mmi->ptMinTrackSize.y = 150;
            return 0;
        }

        case WM_INITMENUPOPUP: {
            SyncMenu();
            HMENU actions = GetSubMenu(hmenu_, 0);
            if ((HMENU)wp == actions) {
                /* Rebuilt each popup: widget block (capture lock first), then
                   the static Send Ctrl+Alt+Del. DeleteMenu also frees the
                   per-widget submenus it created last time. */
                while (GetMenuItemCount(actions) > 0)
                    DeleteMenu(actions, 0, MF_BYPOSITION);
                emu_.Get<HostWidgetRegistry>().AppendAllToMenu(actions);
                AppendMenuW(actions, MF_SEPARATOR, 0, nullptr);
                AppendMenuW(actions, MF_STRING, kIdCtrlAltDel,
                            L"Send Ctrl+Alt+Del\tRight Ctrl+Del");
            }
            return 0;
        }

        case WM_COMMAND:
            if (HIWORD(wp) == 0) {  /* menu item */
                const int id = LOWORD(wp);
                auto& reg = emu_.Get<HostWidgetRegistry>();
                if (reg.OwnsCommand(id)) reg.Dispatch(id);
                else                     HandleCommand(id);
                return 0;
            }
            break;

        case WM_CLOSE:
            /* Without RequestStop the JIT thread keeps grinding ARM code
               after the HWND is destroyed and orphans cerf.exe. */
            if (auto* jit = emu_.TryGet<JitRunner>()) jit->RequestStop();
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            emu_.Get<HostInputCapture>().DetachUiThread();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
