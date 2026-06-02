#define NOMINMAX

#include "host_dark_mode.h"

#include "../core/cerf_emulator.h"

#include <uxtheme.h>

REGISTER_SERVICE(HostDarkMode);

namespace {

/* Undocumented UAH menu messages + structs (ysc3839/win32-darkmode). */
constexpr UINT kWmUahDrawMenu     = 0x0091;
constexpr UINT kWmUahDrawMenuItem = 0x0092;

union UAHMENUITEMMETRICS {
    struct { DWORD cx, cy; } rgsizeBar[2];
    struct { DWORD cx, cy; } rgsizePopup[4];
};
struct UAHMENUPOPUPMETRICS { DWORD rgcx[4]; DWORD fUpdateMaxWidths : 2; };
struct UAHMENU      { HMENU hmenu; HDC hdc; DWORD dwFlags; };
struct UAHMENUITEM  { int iPosition; UAHMENUITEMMETRICS umim; UAHMENUPOPUPMETRICS umpm; };
struct UAHDRAWMENUITEM { DRAWITEMSTRUCT dis; UAHMENU um; UAHMENUITEM umi; };

constexpr COLORREF kClrBar      = RGB(32, 32, 32);
constexpr COLORREF kClrHot      = RGB(60, 60, 60);
constexpr COLORREF kClrSel      = RGB(70, 70, 70);
constexpr COLORREF kClrText     = RGB(230, 230, 230);
constexpr COLORREF kClrDisabled = RGB(120, 120, 120);

using SetPreferredAppMode_t           = int  (WINAPI*)(int);
using AllowDarkModeForWindow_t        = BOOL (WINAPI*)(HWND, BOOL);
using FlushMenuThemes_t               = void (WINAPI*)();
using RefreshImmersiveColorPolicy_t   = void (WINAPI*)();

SetPreferredAppMode_t         g_SetPreferredAppMode      = nullptr;
AllowDarkModeForWindow_t      g_AllowDarkModeForWindow   = nullptr;
FlushMenuThemes_t             g_FlushMenuThemes          = nullptr;
RefreshImmersiveColorPolicy_t g_RefreshImmersivePolicy   = nullptr;

}  /* namespace */

HostDarkMode::~HostDarkMode() {
    if (bar_brush_) DeleteObject(bar_brush_);
    if (hot_brush_) DeleteObject(hot_brush_);
    if (sel_brush_) DeleteObject(sel_brush_);
    if (menu_font_) DeleteObject(menu_font_);
}

void HostDarkMode::EnsureResources() {
    if (!bar_brush_) bar_brush_ = CreateSolidBrush(kClrBar);
    if (!hot_brush_) hot_brush_ = CreateSolidBrush(kClrHot);
    if (!sel_brush_) sel_brush_ = CreateSolidBrush(kClrSel);
    if (!menu_font_) {
        NONCLIENTMETRICSW ncm = { sizeof(ncm) };
        if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
            menu_font_ = CreateFontIndirectW(&ncm.lfMenuFont);
    }
}

void HostDarkMode::Init() {
    if (inited_) return;
    HMODULE ux = LoadLibraryExW(L"uxtheme.dll", nullptr,
                                LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!ux) return;
    g_SetPreferredAppMode    = (SetPreferredAppMode_t)GetProcAddress(ux, MAKEINTRESOURCEA(135));
    g_AllowDarkModeForWindow = (AllowDarkModeForWindow_t)GetProcAddress(ux, MAKEINTRESOURCEA(133));
    g_FlushMenuThemes        = (FlushMenuThemes_t)GetProcAddress(ux, MAKEINTRESOURCEA(136));
    g_RefreshImmersivePolicy = (RefreshImmersiveColorPolicy_t)GetProcAddress(ux, MAKEINTRESOURCEA(104));
    if (!g_SetPreferredAppMode) return;  /* OS too old; leave light */

    g_SetPreferredAppMode(2);  /* PreferredAppMode::ForceDark */
    if (g_RefreshImmersivePolicy) g_RefreshImmersivePolicy();
    EnsureResources();
    inited_ = true;
}

void HostDarkMode::ApplyToWindow(HWND h) {
    if (!inited_ || !h) return;
    if (g_AllowDarkModeForWindow) g_AllowDarkModeForWindow(h, TRUE);
    SetWindowTheme(h, L"DarkMode_Explorer", nullptr);
    if (g_FlushMenuThemes) g_FlushMenuThemes();
}

bool HostDarkMode::HandleMessage(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                 LRESULT& out) {
    if (!inited_) return false;

    switch (msg) {
        case kWmUahDrawMenu: {
            auto* pudm = reinterpret_cast<UAHMENU*>(lp);
            MENUBARINFO mbi = { sizeof(mbi) };
            GetMenuBarInfo(hwnd, OBJID_MENU, 0, &mbi);
            RECT wr; GetWindowRect(hwnd, &wr);
            RECT rc = mbi.rcBar;
            OffsetRect(&rc, -wr.left, -wr.top);
            FillRect(pudm->hdc, &rc, bar_brush_);
            out = TRUE;
            return true;
        }

        case kWmUahDrawMenuItem: {
            auto* p = reinterpret_cast<UAHDRAWMENUITEM*>(lp);
            wchar_t buf[256] = {};
            MENUITEMINFOW mii = { sizeof(mii) };
            mii.fMask = MIIM_STRING;
            mii.dwTypeData = buf;
            mii.cch = 255;
            GetMenuItemInfoW(p->um.hmenu, (UINT)p->umi.iPosition, TRUE, &mii);

            HBRUSH bg = bar_brush_;
            if (p->dis.itemState & ODS_SELECTED)            bg = sel_brush_;
            else if (p->dis.itemState & ODS_HOTLIGHT)       bg = hot_brush_;
            FillRect(p->um.hdc, &p->dis.rcItem, bg);

            UINT dt = DT_CENTER | DT_SINGLELINE | DT_VCENTER;
            if (p->dis.itemState & ODS_NOACCEL) dt |= DT_HIDEPREFIX;
            const COLORREF txt =
                (p->dis.itemState & (ODS_GRAYED | ODS_DISABLED))
                    ? kClrDisabled : kClrText;

            HGDIOBJ old_font = menu_font_
                ? SelectObject(p->um.hdc, menu_font_) : nullptr;
            const int old_bk = SetBkMode(p->um.hdc, TRANSPARENT);
            const COLORREF old_txt = SetTextColor(p->um.hdc, txt);
            RECT rc = p->dis.rcItem;
            DrawTextW(p->um.hdc, buf, -1, &rc, dt);
            SetTextColor(p->um.hdc, old_txt);
            SetBkMode(p->um.hdc, old_bk);
            if (old_font) SelectObject(p->um.hdc, old_font);
            out = TRUE;
            return true;
        }

        case WM_NCPAINT:
        case WM_NCACTIVATE: {
            out = DefWindowProcW(hwnd, msg, wp, lp);
            MENUBARINFO mbi = { sizeof(mbi) };
            if (GetMenuBarInfo(hwnd, OBJID_MENU, 0, &mbi)) {
                RECT wr; GetWindowRect(hwnd, &wr);
                RECT rc = mbi.rcBar;
                OffsetRect(&rc, -wr.left, -wr.top);
                rc.top = rc.bottom;       /* the 1px line under the bar */
                rc.bottom = rc.top + 1;
                HDC hdc = GetWindowDC(hwnd);
                FillRect(hdc, &rc, bar_brush_);
                ReleaseDC(hwnd, hdc);
            }
            return true;
        }

        case WM_THEMECHANGED:
            if (g_FlushMenuThemes) g_FlushMenuThemes();
            return false;
    }
    return false;
}
