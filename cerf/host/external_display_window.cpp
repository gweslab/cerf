#define NOMINMAX

#include "external_display_window.h"

#include <vector>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "frame_source.h"
#include "host_dark_mode.h"
#include "host_dpi.h"
#include "host_key_binding.h"
#include "host_screenshot.h"
#include "host_window.h"

namespace {

constexpr wchar_t kWindowClass[] = L"CerfExternalDisplay";

/* View-menu command ids (local to this window). */
constexpr int kIdVpOriginal = 110;
constexpr int kIdVpAspect   = 111;
constexpr int kIdVpStretch  = 112;
constexpr int kIdVpInteger2 = 113;
constexpr int kIdVpInteger3 = 114;
constexpr int kIdVpInteger5 = 115;
constexpr int kIdAliasing   = 120;
constexpr int kIdFullscreen = 121;
constexpr int kIdSaveShot   = 130;
constexpr int kIdCopyShot   = 131;

/* Cross-thread marshalling messages. */
constexpr UINT kSetSurfaceMsg = WM_APP + 1;   /* wParam=w, lParam=h */
constexpr UINT kSetTitleMsg   = WM_APP + 2;
constexpr UINT kDestroyMsg    = WM_APP + 3;   /* eject: real teardown */

}  /* namespace */

ExternalDisplayWindow::ExternalDisplayWindow(CerfEmulator& emu,
                                             FrameSource& source,
                                             std::wstring title,
                                             std::function<void()> on_eject)
    : emu_(emu), source_(source), on_eject_(std::move(on_eject)),
      title_(std::move(title)), canvas_(&source_, /*host=*/nullptr) {}

ExternalDisplayWindow::~ExternalDisplayWindow() { Close(); }

void ExternalDisplayWindow::Open(uint32_t surf_w, uint32_t surf_h) {
    if (ui_thread_.joinable()) return;
    ui_ready_.store(false);
    ui_thread_ = std::thread([this, surf_w, surf_h] {
        UiThreadMain(surf_w, surf_h);
    });
    std::unique_lock<std::mutex> lk(ui_ready_mutex_);
    ui_ready_cv_.wait(lk, [&] { return ui_ready_.load(); });
}

void ExternalDisplayWindow::Close() {
    if (ui_thread_.joinable()) {
        if (hwnd_) PostMessageW(hwnd_, kDestroyMsg, 0, 0);
        ui_thread_.join();
    }
}

void ExternalDisplayWindow::SetSurfaceSize(uint32_t w, uint32_t h) {
    if (hwnd_) PostMessageW(hwnd_, kSetSurfaceMsg, (WPARAM)w, (LPARAM)h);
}

void ExternalDisplayWindow::SetTitle(std::wstring title) {
    {
        std::lock_guard<std::mutex> lk(title_mutex_);
        title_ = std::move(title);
    }
    if (hwnd_) PostMessageW(hwnd_, kSetTitleMsg, 0, 0);
}

HMENU ExternalDisplayWindow::BuildMenu() {
    HMENU bar  = CreateMenu();
    HMENU view = CreatePopupMenu();
    AppendMenuW(view, MF_STRING, kIdVpOriginal, L"Original view");
    AppendMenuW(view, MF_STRING, kIdVpAspect,   L"Resize + match aspect ratio");
    AppendMenuW(view, MF_STRING, kIdVpStretch,  L"Stretch");
    AppendMenuW(view, MF_STRING, kIdVpInteger2, L"Integer scale 2x");
    AppendMenuW(view, MF_STRING, kIdVpInteger3, L"Integer scale 3x");
    AppendMenuW(view, MF_STRING, kIdVpInteger5, L"Integer scale 5x");
    AppendMenuW(view, MF_STRING, kIdAliasing,   L"Apply aliasing");
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdFullscreen,
                (L"Full screen\t" +
                 emu_.Get<HostKeyBinding>().LabelWith(L"F")).c_str());
    AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view, MF_STRING, kIdSaveShot,   L"Save screenshot");
    AppendMenuW(view, MF_STRING, kIdCopyShot,   L"Copy screenshot");
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)view, L"View");
    return bar;
}

void ExternalDisplayWindow::SyncMenuChecks() {
    HMENU bar = GetMenu(hwnd_);
    HMENU view = bar ? GetSubMenu(bar, 0) : nullptr;
    if (!view) return;
    int vp_id = kIdVpOriginal;
    switch (canvas_.Mode()) {
        case PresenterCanvas::ViewportMode::Original: vp_id = kIdVpOriginal; break;
        case PresenterCanvas::ViewportMode::Aspect:   vp_id = kIdVpAspect;   break;
        case PresenterCanvas::ViewportMode::Stretch:  vp_id = kIdVpStretch;  break;
        case PresenterCanvas::ViewportMode::Integer:
            if (canvas_.IntegerFactor() >= 5)      vp_id = kIdVpInteger5;
            else if (canvas_.IntegerFactor() >= 3) vp_id = kIdVpInteger3;
            else                                   vp_id = kIdVpInteger2;
            break;
    }
    CheckMenuRadioItem(view, kIdVpOriginal, kIdVpInteger5, vp_id, MF_BYCOMMAND);
    CheckMenuItem(view, kIdAliasing,
                  MF_BYCOMMAND | (canvas_.Antialias() ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(view, kIdFullscreen,
                  MF_BYCOMMAND | (fullscreen_.IsActive() ? MF_CHECKED : MF_UNCHECKED));
}

void ExternalDisplayWindow::FitToSurface(uint32_t sw, uint32_t sh) {
    if (!hwnd_ || sw == 0 || sh == 0 || fullscreen_.IsActive()) return;

    const DWORD style = (DWORD)GetWindowLongW(hwnd_, GWL_STYLE);
    const DWORD ex    = (DWORD)GetWindowLongW(hwnd_, GWL_EXSTYLE);
    RECT r = { 0, 0, (LONG)sw, (LONG)sh };
    auto& dpi = emu_.Get<HostDpi>();
    dpi.AdjustForDpi(r, style, /*bMenu=*/TRUE, ex, dpi.ForWindow(hwnd_));
    int outer_w = (int)(r.right - r.left);
    int outer_h = (int)(r.bottom - r.top);

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

void ExternalDisplayWindow::UiThreadMain(uint32_t surf_w, uint32_t surf_h) {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = &ExternalDisplayWindow::WndProcStatic;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon         = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1));
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = kWindowClass;
    if (RegisterClassExW(&wc) == 0) {
        const DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            LOG(Caution, "ExternalDisplayWindow: RegisterClassExW failed "
                "(gle=%lu)\n", err);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }

    std::wstring title;
    { std::lock_guard<std::mutex> lk(title_mutex_); title = title_; }

    const DWORD style = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
    HMENU menu = BuildMenu();
    hwnd_ = CreateWindowExW(0, kWindowClass, title.c_str(), style,
                            CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
                            nullptr, menu, GetModuleHandleW(nullptr), this);
    if (!hwnd_) {
        LOG(Caution, "ExternalDisplayWindow: CreateWindowExW failed (gle=%lu)\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    emu_.Get<HostDarkMode>().ApplyToWindow(hwnd_);  /* dark title bar + theme */

    FitToSurface(surf_w, surf_h);

    RECT rc;
    GetClientRect(hwnd_, &rc);
    canvas_.CreateOn(hwnd_, rc, surf_w, surf_h);
    emu_.Get<HostDarkMode>().ApplyToWindow(canvas_.Hwnd());

    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);

    {
        std::lock_guard<std::mutex> lk(ui_ready_mutex_);
        ui_ready_.store(true);
    }
    ui_ready_cv_.notify_all();

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if ((msg.message == WM_KEYDOWN || msg.message == WM_SYSKEYDOWN) &&
            msg.wParam == 'F' &&
            emu_.Get<HostKeyBinding>().AllMembersDownNow()) {
            fullscreen_.Toggle(hwnd_);
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

LRESULT CALLBACK ExternalDisplayWindow::WndProcStatic(HWND hwnd, UINT msg,
                                                      WPARAM wp, LPARAM lp) {
    ExternalDisplayWindow* self = nullptr;
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        self = static_cast<ExternalDisplayWindow*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<ExternalDisplayWindow*>(
                   GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    return self ? self->WndProc(hwnd, msg, wp, lp)
                : DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT ExternalDisplayWindow::WndProc(HWND hwnd, UINT msg,
                                       WPARAM wp, LPARAM lp) {
    LRESULT dark_out = 0;
    if (emu_.Get<HostDarkMode>().HandleMessage(hwnd, msg, wp, lp, dark_out))
        return dark_out;

    if (msg == kSetSurfaceMsg) {
        const uint32_t w = (uint32_t)wp, h = (uint32_t)lp;
        if (w && h) {
            canvas_.SetGuestSurfaceSize(w, h);
            FitToSurface(canvas_.ContentWidth(), canvas_.ContentHeight());
        }
        return 0;
    }
    if (msg == kSetTitleMsg) {
        std::lock_guard<std::mutex> lk(title_mutex_);
        SetWindowTextW(hwnd, title_.c_str());
        return 0;
    }
    if (msg == kDestroyMsg) {
        DestroyWindow(hwnd);
        return 0;
    }

    switch (msg) {
        case WM_SIZE: {
            RECT rc;
            GetClientRect(hwnd, &rc);
            canvas_.Reposition(rc);
            return 0;
        }
        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
            mmi->ptMinTrackSize.x = 160;
            mmi->ptMinTrackSize.y = 120;
            return 0;
        }
        case WM_INITMENUPOPUP:
            SyncMenuChecks();
            return 0;
        case WM_COMMAND:
            if (HIWORD(wp) == 0) {  /* menu item */
                switch (LOWORD(wp)) {
                    case kIdVpOriginal:
                        canvas_.SetViewportMode(PresenterCanvas::ViewportMode::Original); break;
                    case kIdVpAspect:
                        canvas_.SetViewportMode(PresenterCanvas::ViewportMode::Aspect); break;
                    case kIdVpStretch:
                        canvas_.SetViewportMode(PresenterCanvas::ViewportMode::Stretch); break;
                    case kIdVpInteger2:
                        canvas_.SetIntegerScale(2);
                        FitToSurface(canvas_.ContentWidth(), canvas_.ContentHeight());
                        break;
                    case kIdVpInteger3:
                        canvas_.SetIntegerScale(3);
                        FitToSurface(canvas_.ContentWidth(), canvas_.ContentHeight());
                        break;
                    case kIdVpInteger5:
                        canvas_.SetIntegerScale(5);
                        FitToSurface(canvas_.ContentWidth(), canvas_.ContentHeight());
                        break;
                    case kIdAliasing:
                        canvas_.SetAntialias(!canvas_.Antialias()); break;
                    case kIdFullscreen: fullscreen_.Toggle(hwnd); break;
                    case kIdSaveShot: {
                        std::vector<uint32_t> px;
                        uint32_t w = 0, h = 0;
                        if (canvas_.CaptureSurface(px, w, h)) {
                            std::wstring name;
                            { std::lock_guard<std::mutex> lk(title_mutex_);
                              name = title_; }
                            emu_.Get<HostScreenshot>().SavePixels(px, w, h, name);
                        }
                        break;
                    }
                    case kIdCopyShot: {
                        std::vector<uint32_t> px;
                        uint32_t w = 0, h = 0;
                        if (canvas_.CaptureSurface(px, w, h))
                            emu_.Get<HostScreenshot>().CopyPixels(px, w, h, hwnd);
                        break;
                    }
                }
                return 0;
            }
            break;
        case WM_CLOSE: {
            /* Closing the window means ejecting the card; the eject (run on the
               main UI thread) destroys this card and joins THIS thread, so it
               must not run here. Returning 0 suppresses DefWindowProc's
               DestroyWindow - teardown happens via kDestroyMsg from Close(). */
            std::wstring caption;
            { std::lock_guard<std::mutex> lk(title_mutex_); caption = title_; }
            if (MessageBoxW(hwnd, L"Eject VGA card?", caption.c_str(),
                            MB_YESNO | MB_ICONQUESTION) == IDYES && on_eject_)
                emu_.Get<HostWindow>().RunOnUiThread(on_eject_);
            return 0;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
