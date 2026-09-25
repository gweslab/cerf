#define NOMINMAX
#include "modal_dialog.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "host_dark_mode.h"
#include "host_dpi.h"
#include "host_link_opener.h"

#include <commctrl.h>

void ModalDialog::PostDismiss() {
    if (hwnd_) PostMessageW(hwnd_, WM_CLOSE, 0, 0);
}

void ModalDialog::RunModal(HWND owner, const wchar_t* class_name,
                           const wchar_t* title, int client_w, int client_h) {
    if (hwnd_) {
        LOG(Caution, "ModalDialog::RunModal re-entered while '%ls' is open\n",
            title);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = &ModalDialog::WndProcStatic;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hIcon         = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1));
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = class_name;
    RegisterClassExW(&wc);

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LINK_CLASS };
    InitCommonControlsEx(&icc);

    done_ = false;
    dpi_  = emu_.Get<HostDpi>().ForWindow(owner);

    const DWORD style = WS_CAPTION | WS_SYSMENU | WS_DLGFRAME | WS_POPUP;
    RECT wr = { 0, 0, client_w, client_h };
    emu_.Get<HostDpi>().AdjustForDpi(wr, style, FALSE, WS_EX_DLGMODALFRAME, dpi_);
    const int ww = wr.right - wr.left;
    const int wh = wr.bottom - wr.top;
    RECT orc = { 0, 0, 0, 0 };
    GetWindowRect(owner, &orc);
    const int x = orc.left + ((orc.right - orc.left) - ww) / 2;
    const int y = orc.top  + ((orc.bottom - orc.top) - wh) / 2;

    EnableWindow(owner, FALSE);
    hwnd_ = CreateWindowExW(WS_EX_DLGMODALFRAME, class_name, title, style,
                            x, y, ww, wh, owner, nullptr,
                            GetModuleHandleW(nullptr), this);
    if (!hwnd_) {
        EnableWindow(owner, TRUE);
        return;
    }

    BuildControls(hwnd_);
    emu_.Get<HostDarkMode>().ApplyToDialog(hwnd_);
    ApplyDpiFont();
    ShowWindow(hwnd_, SW_SHOW);
    SetForegroundWindow(hwnd_);
    OnShown();

    MSG msg;
    while (!done_ && GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(hwnd_, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    DestroyWindow(hwnd_);
    hwnd_ = nullptr;
    if (dpi_font_) { DeleteObject(dpi_font_); dpi_font_ = nullptr; }
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
}

BOOL CALLBACK ModalDialog::SetChildFontProc(HWND child, LPARAM font) {
    SendMessageW(child, WM_SETFONT, (WPARAM)font, TRUE);
    return TRUE;
}

void ModalDialog::ApplyDpiFont() {
    if (!DpiScaledLayout()) return;
    NONCLIENTMETRICSW ncm = { sizeof(ncm) };
    if (!emu_.Get<HostDpi>().NonClientMetricsForDpi(ncm, dpi_)) return;
    dpi_font_ = CreateFontIndirectW(&ncm.lfMessageFont);
    if (dpi_font_)
        EnumChildWindows(hwnd_, &ModalDialog::SetChildFontProc, (LPARAM)dpi_font_);
}

LRESULT ModalDialog::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (OnMessage(msg, wp, lp)) return 0;
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            OnPaint(dc);
            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_DRAWITEM:
            if (OnDrawItem(reinterpret_cast<DRAWITEMSTRUCT*>(lp))) return TRUE;
            break;

        case WM_COMMAND:
            OnCommand(LOWORD(wp), HIWORD(wp));
            return 0;

        case WM_NOTIFY: {
            const auto* nh = reinterpret_cast<const NMHDR*>(lp);
            wchar_t cls[16] = {};
            GetClassNameW(nh->hwndFrom, cls, 16);
            if (lstrcmpiW(cls, WC_LINK) != 0) break;
            if (nh->code == NM_CLICK || nh->code == NM_RETURN) {
                emu_.Get<HostLinkOpener>().OpenNotified(hwnd, lp);
                return 0;
            }
            if (nh->code == NM_CUSTOMDRAW) {
                LRESULT out = 0;
                if (emu_.Get<HostDarkMode>().HandleLinkCustomDraw(lp, out))
                    return out;
            }
            break;
        }

        case WM_CLOSE:
            done_ = true;
            return 0;

        case WM_ERASEBKGND:
            if (emu_.Get<HostDarkMode>().EraseBackground((HDC)wp, hwnd)) return 1;
            break;

        case WM_CTLCOLORDLG:
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN:
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORLISTBOX: {
            LRESULT br;
            if (emu_.Get<HostDarkMode>().HandleCtlColor(msg, wp, br)) return br;
            break;
        }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT CALLBACK ModalDialog::WndProcStatic(HWND hwnd, UINT msg, WPARAM wp,
                                            LPARAM lp) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
    }
    auto* self =
        reinterpret_cast<ModalDialog*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (self) return self->WndProc(hwnd, msg, wp, lp);
    return DefWindowProcW(hwnd, msg, wp, lp);
}
