#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"
#include <commctrl.h>
#include <dwmapi.h>
#pragma comment(lib, "comctl32")
#pragma comment(lib, "dwmapi")

/* ---------- WS_EX_CAPTIONOKBTN title bar button via window subclassing ---------- */

#define CAPTIONOK_SUBCLASS_ID 0xCE0F0001
#define HT_CAPTIONOK          0x0200      /* custom WM_NCHITTEST return value */

/* Per-window offset from the right edge of the window to the left edge of
   native title bar buttons (?, X).  Cached during InstallCaptionOk by probing
   WM_NCHITTEST, since SM_CXSIZE doesn't match the actual classic-mode button
   widths on Windows 10/11 with DWM disabled. */
/* Calculate the OK button rect in window (not screen) coordinates.
   Uses the same button-position formula as PaintThemedCaption so the
   OK button sits exactly to the left of the themed caption buttons. */
static RECT GetCaptionOkBtnRect(HWND hwnd) {
    int captH = GetSystemMetrics(SM_CYCAPTION);
    int padBorder = GetSystemMetrics(SM_CXPADDEDBORDER);
    int frame = GetSystemMetrics(SM_CXFRAME) + padBorder;
    int btnW = GetSystemMetrics(SM_CXSIZE) - 2;
    RECT wr;
    GetWindowRect(hwnd, &wr);
    int winW = wr.right - wr.left;
    int captRight = winW - frame;
    int border_top = GetSystemMetrics(SM_CYFRAME) + padBorder;

    /* Count native buttons — same logic as PaintThemedCaption */
    LONG style = GetWindowLongW(hwnd, GWL_STYLE);
    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
    int btnX = captRight - 2;
    if (style & WS_SYSMENU) btnX -= btnW;
    if (exStyle & WS_EX_CONTEXTHELP) btnX -= btnW;
    if (style & WS_MAXIMIZEBOX) btnX -= btnW;
    if (style & WS_MINIMIZEBOX) btnX -= btnW;

    /* OK button goes immediately to the left of the leftmost native button */
    int okW = captH;
    RECT r;
    r.right = btnX;
    r.left  = r.right - okW;
    r.top   = border_top;
    r.bottom = r.top + captH;
    return r;
}

static void PaintCaptionOkBtn(HWND hwnd) {
    HDC hdc = GetWindowDC(hwnd);
    if (!hdc) return;
    bool active = (GetForegroundWindow() == hwnd);
    RECT r = GetCaptionOkBtnRect(hwnd);
    /* Button face */
    HBRUSH br = CreateSolidBrush(GetSysColor(COLOR_BTNFACE));
    FillRect(hdc, &r, br);
    DeleteObject(br);
    DrawEdge(hdc, &r, BDR_RAISEDOUTER, BF_RECT);
    /* "OK" label */
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, GetSysColor(active ? COLOR_BTNTEXT : COLOR_GRAYTEXT));
    HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    DrawTextW(hdc, L"OK", 2, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, oldFont);
    ReleaseDC(hwnd, hdc);
}

LRESULT CALLBACK Win32Thunks::CaptionOkSubclassProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR subclassId, DWORD_PTR refData)
{
    switch (msg) {
    case WM_NCHITTEST: {
        LRESULT def = DefSubclassProc(hwnd, msg, wParam, lParam);
        /* Only override hits in the caption area (not on native buttons) */
        if (def == HTCAPTION) {
            int ptx = (int)(short)LOWORD(lParam);
            int pty = (int)(short)HIWORD(lParam);
            RECT wr;
            GetWindowRect(hwnd, &wr);
            POINT pt = { ptx - wr.left, pty - wr.top };
            RECT okRect = GetCaptionOkBtnRect(hwnd);
            if (PtInRect(&okRect, pt))
                return HT_CAPTIONOK;
        }
        return def;
    }
    case WM_NCLBUTTONDOWN:
        if (wParam == HT_CAPTIONOK) {
            LOG(API, "[API] CaptionOK clicked on HWND=0x%p, posting WM_COMMAND(IDOK)\n", hwnd);
            PostMessageW(hwnd, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), 0);
            return 0;
        }
        break;
    case WM_NCPAINT:
        DefSubclassProc(hwnd, msg, wParam, lParam);
        PaintCaptionOkBtn(hwnd);
        return 0;
    case WM_NCACTIVATE: {
        LRESULT r = DefSubclassProc(hwnd, msg, wParam, lParam);
        PaintCaptionOkBtn(hwnd);
        return r;
    }
    case WM_SIZE:
    case WM_MOVE: {
        LRESULT r = DefSubclassProc(hwnd, msg, wParam, lParam);
        PaintCaptionOkBtn(hwnd);
        return r;
    }
    case WM_NCDESTROY:
        RemoveWindowSubclass(hwnd, CaptionOkSubclassProc, CAPTIONOK_SUBCLASS_ID);
        break;
    }
    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

void Win32Thunks::InstallCaptionOk(HWND hwnd) {
    /* Disable DWM non-client rendering so our GDI title-bar painting is visible.
       Without this, DWM on Windows 10/11 paints over our custom NC area. */
    DWMNCRENDERINGPOLICY policy = DWMNCRP_DISABLED;
    DwmSetWindowAttribute(hwnd, DWMWA_NCRENDERING_POLICY, &policy, sizeof(policy));
    /* Force frame recalculation */
    SetWindowPos(hwnd, NULL, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);

    SetWindowSubclass(hwnd, CaptionOkSubclassProc, CAPTIONOK_SUBCLASS_ID, 0);
    PaintCaptionOkBtn(hwnd);
}

void Win32Thunks::RemoveCaptionOk(HWND hwnd) {
    RemoveWindowSubclass(hwnd, CaptionOkSubclassProc, CAPTIONOK_SUBCLASS_ID);
    /* Re-enable DWM non-client rendering */
    DWMNCRENDERINGPOLICY policy = DWMNCRP_ENABLED;
    DwmSetWindowAttribute(hwnd, DWMWA_NCRENDERING_POLICY, &policy, sizeof(policy));
}
