/* WinCE NC area painting and hit-testing.
   Split from theme_subclass.cpp to keep files under 300 lines. */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "theme_internal.h"

/* Paint WinCE-style NC area: 1px border + thin caption bar on WS_POPUP windows. */
int PaintWinCENCArea(HWND hwnd) {
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
            HBRUSH btnBrush = CreateSolidBrush(GetThemedColor(COLOR_BTNFACE));
            FillRect(hdc, &btnR, btnBrush);
            DeleteObject(btnBrush);
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
LRESULT HitTestWinCECaption(HWND hwnd, POINT pt) {
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
