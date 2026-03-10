/* WinCE Theme Subclass — NC painting, hit-testing, and ThemeSubclassProc.
   Split from theme.cpp to keep files under 300 lines. */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "theme_internal.h"
#include "../log.h"
#include <commctrl.h>

static thread_local bool g_in_nc_paint = false;
#define HT_CAPTIONOK 0x0200

/* Paint WinCE-style NC area: 1px border + thin caption bar on WS_POPUP windows. */
static int PaintWinCENCArea(HWND hwnd) {
    auto sit = Win32Thunks::hwnd_wce_style_map.find(hwnd);
    if (sit == Win32Thunks::hwnd_wce_style_map.end()) return 0;
    uint32_t wce_style = sit->second;
    bool has_caption = (wce_style & WS_CAPTION) == WS_CAPTION;
    bool has_border = (wce_style & WS_BORDER) != 0;
    if (!has_caption && !has_border) return 0;

    HDC hdc = GetWindowDC(hwnd);
    if (!hdc) return 0;

    RECT wr;
    GetWindowRect(hwnd, &wr);
    int winW = wr.right - wr.left;
    int winH = wr.bottom - wr.top;
    int captH = has_caption ? GetSystemMetrics(SM_CYCAPTION) : 0;
    constexpr int WINCE_BORDER = 1;

    bool active = (GetForegroundWindow() == hwnd);
    COLORREF caption_color = GetThemedColor(active ? COLOR_ACTIVECAPTION : COLOR_INACTIVECAPTION);
    COLORREF text_color = GetThemedColor(active ? COLOR_CAPTIONTEXT : COLOR_INACTIVECAPTIONTEXT);

    /* Draw 1px border around the entire window */
    HBRUSH frameBrush = CreateSolidBrush(GetThemedColor(COLOR_WINDOWFRAME));
    RECT border_rect = {0, 0, winW, winH};
    FrameRect(hdc, &border_rect, frameBrush);
    DeleteObject(frameBrush);

    int btnX = winW; /* default: no buttons */

    if (has_caption) {
        RECT captRect = {WINCE_BORDER, WINCE_BORDER, winW - WINCE_BORDER, WINCE_BORDER + captH};
        HBRUSH captBrush = CreateSolidBrush(caption_color);
        FillRect(hdc, &captRect, captBrush);
        DeleteObject(captBrush);

        /* Caption buttons — square, drawn from right to left */
        int btnH = captH - 4;
        int btnW = btnH;
        int btnY = captRect.top + 2;
        btnX = captRect.right - 2;

        auto eit = Win32Thunks::hwnd_wce_exstyle_map.find(hwnd);
        uint32_t wce_exstyle = (eit != Win32Thunks::hwnd_wce_exstyle_map.end()) ? eit->second : 0;

        /* Close button (X) */
        if (wce_style & WS_SYSMENU) {
            btnX -= btnW;
            RECT btnR = {btnX, btnY, btnX + btnW, btnY + btnH};
            DrawFrameControl(hdc, &btnR, DFC_CAPTION, DFCS_CAPTIONCLOSE);
        }
        /* Help button (?) */
        if (wce_exstyle & WS_EX_CONTEXTHELP) {
            btnX -= btnW;
            RECT btnR = {btnX, btnY, btnX + btnW, btnY + btnH};
            DrawFrameControl(hdc, &btnR, DFC_CAPTION, DFCS_CAPTIONHELP);
        }
        /* OK button (WS_EX_CAPTIONOKBTN = 0x80000000) */
        if (wce_exstyle & 0x80000000) {
            btnX -= btnW;
            RECT btnR = {btnX, btnY, btnX + btnW, btnY + btnH};
            DrawEdge(hdc, &btnR, BDR_RAISEDOUTER, BF_RECT);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, GetThemedColor(active ? COLOR_BTNTEXT : COLOR_GRAYTEXT));
            HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            HFONT oldFont = (HFONT)SelectObject(hdc, font);
            DrawTextW(hdc, L"OK", 2, &btnR, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(hdc, oldFont);
        }

        /* Caption text */
        wchar_t title[256] = {};
        GetWindowTextW(hwnd, title, 256);
        if (title[0]) {
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, text_color);
            static HFONT s_captFont = NULL;
            if (!s_captFont) {
                NONCLIENTMETRICSW ncm = {};
                ncm.cbSize = sizeof(ncm);
                SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
                s_captFont = CreateFontIndirectW(&ncm.lfCaptionFont);
            }
            HFONT oldFont = (HFONT)SelectObject(hdc, s_captFont);
            RECT textRect = captRect;
            textRect.left += 4;
            textRect.right = btnX - 4;
            DrawTextW(hdc, title, -1, &textRect,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
            SelectObject(hdc, oldFont);
        }
    }

    ReleaseDC(hwnd, hdc);
    return btnX;
}

/* Hit-test WinCE caption. Returns HTCAPTION/HTCLOSE/HTHELP/HT_CAPTIONOK or 0. */
static LRESULT HitTestWinCECaption(HWND hwnd, POINT pt) {
    auto sit = Win32Thunks::hwnd_wce_style_map.find(hwnd);
    if (sit == Win32Thunks::hwnd_wce_style_map.end()) return 0;
    uint32_t wce_style = sit->second;
    if ((wce_style & WS_CAPTION) != WS_CAPTION) return 0;

    RECT wr;
    GetWindowRect(hwnd, &wr);
    int winW = wr.right - wr.left;
    int captH = GetSystemMetrics(SM_CYCAPTION);
    constexpr int WINCE_BORDER = 1;

    if (pt.x < WINCE_BORDER || pt.x >= winW - WINCE_BORDER) return 0;
    if (pt.y < WINCE_BORDER || pt.y >= WINCE_BORDER + captH) return 0;

    int btnH = captH - 4, btnW = btnH;
    int btnX = winW - WINCE_BORDER - 2;

    auto eit = Win32Thunks::hwnd_wce_exstyle_map.find(hwnd);
    uint32_t wce_exstyle = (eit != Win32Thunks::hwnd_wce_exstyle_map.end()) ? eit->second : 0;

    if (wce_style & WS_SYSMENU) {
        btnX -= btnW;
        if (pt.x >= btnX && pt.x < btnX + btnW) return HTCLOSE;
    }
    if (wce_exstyle & WS_EX_CONTEXTHELP) {
        btnX -= btnW;
        if (pt.x >= btnX && pt.x < btnX + btnW) return HTHELP;
    }
    if (wce_exstyle & 0x80000000) {
        btnX -= btnW;
        if (pt.x >= btnX && pt.x < btnX + btnW) return HT_CAPTIONOK;
    }

    return HTCAPTION;
}

LRESULT CALLBACK ThemeSubclassProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR subclassId, DWORD_PTR refData)
{
    bool is_toplevel = (refData != 0);

    switch (msg) {

    case WM_NCCALCSIZE:
        if (is_toplevel) {
            auto sit = Win32Thunks::hwnd_wce_style_map.find(hwnd);
            if (sit != Win32Thunks::hwnd_wce_style_map.end()) {
                uint32_t ws = sit->second;
                bool has_caption = (ws & WS_CAPTION) == WS_CAPTION;
                bool has_border = (ws & WS_BORDER) != 0;
                if (has_caption || has_border) {
                    int border = 1;
                    int caption = has_caption ? GetSystemMetrics(SM_CYCAPTION) : 0;
                    if (wParam) {
                        NCCALCSIZE_PARAMS* ncp = (NCCALCSIZE_PARAMS*)lParam;
                        ncp->rgrc[0].left += border;
                        ncp->rgrc[0].top += border + caption;
                        ncp->rgrc[0].right -= border;
                        ncp->rgrc[0].bottom -= border;
                    } else {
                        RECT* rc = (RECT*)lParam;
                        rc->left += border;
                        rc->top += border + caption;
                        rc->right -= border;
                        rc->bottom -= border;
                    }
                    return 0;
                }
            }
        }
        break;

    /* WM_CTLCOLOR*: return themed brushes (kernel bypasses our hook). */
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, GetThemedColor(COLOR_3DFACE));
        SetTextColor(hdc, GetThemedColor(COLOR_WINDOWTEXT));
        return (LRESULT)GetThemedBrush(COLOR_3DFACE);
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, GetThemedColor(COLOR_WINDOW));
        SetTextColor(hdc, GetThemedColor(COLOR_WINDOWTEXT));
        return (LRESULT)GetThemedBrush(COLOR_WINDOW);
    }
    case WM_CTLCOLORSCROLLBAR:
        return (LRESULT)GetThemedBrush(COLOR_SCROLLBAR);

    /* WM_ERASEBKGND: fill with themed color. */
    case WM_ERASEBKGND: {
        ULONG_PTR cls_brush = GetClassLongPtrW(hwnd, GCLP_HBRBACKGROUND);
        int color_idx = COLOR_3DFACE;
        if (cls_brush >= 1 && cls_brush <= 31) {
            color_idx = (int)cls_brush - 1;
            if (color_idx >= WCE_NUM_SYSCOLORS) color_idx = COLOR_3DFACE;
        } else if (cls_brush == 0) {
            break;
        } else {
            break;
        }
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, GetThemedBrush(color_idx));
        return 1;
    }

    /* Push button face overpaint for themed COLOR_BTNFACE. */
    case WM_PAINT: {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        if (wcscmp(cls, L"Button") == 0) {
            LONG bs = GetWindowLongW(hwnd, GWL_STYLE) & BS_TYPEMASK;
            if (bs == BS_PUSHBUTTON || bs == BS_DEFPUSHBUTTON) {
                LRESULT lr = DefSubclassProc(hwnd, msg, wParam, lParam);
                RECT rc;
                GetClientRect(hwnd, &rc);
                int edge = GetSystemMetrics(SM_CXEDGE);
                InflateRect(&rc, -edge, -edge);
                HDC hdc = GetDC(hwnd);
                FillRect(hdc, &rc, GetThemedBrush(COLOR_BTNFACE));
                wchar_t text[256] = {};
                GetWindowTextW(hwnd, text, 256);
                if (text[0]) {
                    HFONT font = (HFONT)SendMessageW(hwnd, WM_GETFONT, 0, 0);
                    HFONT oldFont = font ? (HFONT)SelectObject(hdc, font) : NULL;
                    SetBkMode(hdc, TRANSPARENT);
                    SetTextColor(hdc, GetThemedColor(COLOR_BTNTEXT));
                    DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                    if (oldFont) SelectObject(hdc, oldFont);
                }
                ReleaseDC(hwnd, hdc);
                return lr;
            }
        }
        break;
    }

    /* WM_NCPAINT / WM_NCACTIVATE: draw WinCE NC area. */
    case WM_NCPAINT:
    case WM_NCACTIVATE:
        if (is_toplevel && !g_in_nc_paint) {
            g_in_nc_paint = true;
            LRESULT lr = DefSubclassProc(hwnd, msg, wParam, lParam);
            PaintWinCENCArea(hwnd);
            g_in_nc_paint = false;
            return lr;
        }
        break;

    /* WM_NCHITTEST: run custom hit-test BEFORE DefSubclassProc because
       DefWindowProc may return HTNOWHERE for the NC area of WS_POPUP. */
    case WM_NCHITTEST: {
        if (is_toplevel) {
            RECT wr;
            GetWindowRect(hwnd, &wr);
            POINT pt = {(int)(short)LOWORD(lParam) - wr.left,
                        (int)(short)HIWORD(lParam) - wr.top};
            LRESULT nc = HitTestWinCECaption(hwnd, pt);
            if (nc) return nc;
        }
        return DefSubclassProc(hwnd, msg, wParam, lParam);
    }

    /* WM_NCLBUTTONDOWN: handle clicks on WinCE caption buttons */
    case WM_NCLBUTTONDOWN:
        if (wParam == HTCLOSE) {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
            return 0;
        }
        if (wParam == HT_CAPTIONOK) {
            PostMessageW(hwnd, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), 0);
            return 0;
        }
        break;

    case WM_NCDESTROY:
        RemoveWindowSubclass(hwnd, ThemeSubclassProc, THEME_SUBCLASS_ID);
        break;
    }

    return DefSubclassProc(hwnd, msg, wParam, lParam);
}
