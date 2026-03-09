/* WinCE Theme Engine
   Loads system colors from the WinCE registry (HKLM\SYSTEM\GWE\SysColor)
   and applies them per-process. Zero global side effects.

   Hybrid approach:
   1. Inline-hook GetSysColor/GetSysColorBrush in user32.dll (copy-on-write).
      This makes controls that call GetSysColor internally (push buttons,
      scrollbars, etc.) use our WinCE colors automatically.
   2. Minimal window subclass for things the hooks can't reach:
      - WM_ERASEBKGND: DefWindowProc resolves class pseudo-brushes from the
        kernel-side color table, bypassing GetSysColor. We override it.
      - WM_NCPAINT/WM_NCACTIVATE: On DWM systems, DwmSetWindowAttribute
        sets caption color. On non-DWM systems, we paint the caption.
   3. SetWindowTheme strips UxTheme per-window for classic WinCE look.
   No SetSysColors, no global changes. */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"
#include <uxtheme.h>
#include <commctrl.h>
#include <dwmapi.h>
#pragma comment(lib, "uxtheme")
#pragma comment(lib, "comctl32")
#pragma comment(lib, "dwmapi")

#ifndef DWMWA_CAPTION_COLOR
#define DWMWA_CAPTION_COLOR 35
#endif
#ifndef DWMWA_TEXT_COLOR
#define DWMWA_TEXT_COLOR 36
#endif

/* Number of WinCE system color indices (COLOR_SCROLLBAR=0 through COLOR_STATICTEXT=26) */
#define WCE_NUM_SYSCOLORS 27

/* Maximum desktop system color index (COLOR_MENUBAR=30 on modern Windows) */
#define MAX_DESKTOP_SYSCOLORS 31

/* Global theme state */
static bool g_theme_active = false;
static COLORREF g_wce_colors[WCE_NUM_SYSCOLORS];
static HBRUSH g_wce_brushes[WCE_NUM_SYSCOLORS];

/* Cached original desktop system colors (before hooking) */
static COLORREF g_original_colors[MAX_DESKTOP_SYSCOLORS];
static HBRUSH g_original_brushes[MAX_DESKTOP_SYSCOLORS];

/* Default WinCE 5.0 "Windows Standard" system colors.
   COLORREF format: 0x00BBGGRR. */
static const COLORREF wce5_default_colors[WCE_NUM_SYSCOLORS] = {
    0x00C8D0D4, /* 0  COLOR_SCROLLBAR        RGB(212,208,200) silver */
    0x00A56E3A, /* 1  COLOR_BACKGROUND        RGB(58,110,165)  steel blue desktop */
    0x00800000, /* 2  COLOR_ACTIVECAPTION     RGB(0,0,128)     navy blue */
    0x00808080, /* 3  COLOR_INACTIVECAPTION   RGB(128,128,128) gray */
    0x00C8D0D4, /* 4  COLOR_MENU              RGB(212,208,200) silver */
    0x00FFFFFF, /* 5  COLOR_WINDOW            RGB(255,255,255) white */
    0x00000000, /* 6  COLOR_WINDOWFRAME       RGB(0,0,0)       black */
    0x00000000, /* 7  COLOR_MENUTEXT          RGB(0,0,0)       black */
    0x00000000, /* 8  COLOR_WINDOWTEXT        RGB(0,0,0)       black */
    0x00FFFFFF, /* 9  COLOR_CAPTIONTEXT       RGB(255,255,255) white */
    0x00C8D0D4, /* 10 COLOR_ACTIVEBORDER      RGB(212,208,200) silver */
    0x00C8D0D4, /* 11 COLOR_INACTIVEBORDER    RGB(212,208,200) silver */
    0x00808080, /* 12 COLOR_APPWORKSPACE      RGB(128,128,128) gray */
    0x00800000, /* 13 COLOR_HIGHLIGHT         RGB(0,0,128)     navy blue */
    0x00FFFFFF, /* 14 COLOR_HIGHLIGHTTEXT     RGB(255,255,255) white */
    0x00C8D0D4, /* 15 COLOR_BTNFACE           RGB(212,208,200) silver */
    0x00808080, /* 16 COLOR_BTNSHADOW         RGB(128,128,128) gray */
    0x00808080, /* 17 COLOR_GRAYTEXT          RGB(128,128,128) gray */
    0x00000000, /* 18 COLOR_BTNTEXT           RGB(0,0,0)       black */
    0x00C8D0D4, /* 19 COLOR_INACTIVECAPTIONTEXT RGB(212,208,200) silver */
    0x00FFFFFF, /* 20 COLOR_BTNHIGHLIGHT      RGB(255,255,255) white */
    0x00404040, /* 21 COLOR_3DDKSHADOW        RGB(64,64,64)    dark gray */
    0x00C8D0D4, /* 22 COLOR_3DLIGHT           RGB(212,208,200) silver */
    0x00000000, /* 23 COLOR_INFOTEXT          RGB(0,0,0)       black */
    0x00E1FFFF, /* 24 COLOR_INFOBK            RGB(255,255,225) light yellow */
    0x00C8D0D4, /* 25 COLOR_STATIC            RGB(212,208,200) silver */
    0x00000000, /* 26 COLOR_STATICTEXT        RGB(0,0,0)       black */
};

/* ======================================================================
   Themed Brush / Color Helpers
   ====================================================================== */

static HBRUSH GetThemedBrush(int color_idx) {
    if (color_idx < 0 || color_idx >= WCE_NUM_SYSCOLORS) return NULL;
    if (!g_wce_brushes[color_idx])
        g_wce_brushes[color_idx] = CreateSolidBrush(g_wce_colors[color_idx]);
    return g_wce_brushes[color_idx];
}

static COLORREF GetThemedColor(int color_idx) {
    if (color_idx >= 0 && color_idx < WCE_NUM_SYSCOLORS)
        return g_wce_colors[color_idx];
    if (color_idx >= 0 && color_idx < MAX_DESKTOP_SYSCOLORS)
        return g_original_colors[color_idx];
    return 0;
}

/* ======================================================================
   Inline Hook Infrastructure
   Patches the first 12 bytes of a target function with an absolute JMP.
   The modified page becomes a private copy-on-write page for this process.

   x64 patch:  mov rax, <hook_addr>  (48 B8 xx xx xx xx xx xx xx xx)
               jmp rax               (FF E0)
   ====================================================================== */

static bool InstallInlineHook(const char* func_name, void* target, void* hook) {
    if (!target || !hook) {
        LOG(THEME, "[THEME] InstallInlineHook: NULL target or hook for %s\n", func_name);
        return false;
    }

    DWORD old_protect;
    if (!VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &old_protect)) {
        LOG(THEME, "[THEME] VirtualProtect failed for %s: error %d\n", func_name, GetLastError());
        return false;
    }

    BYTE* p = (BYTE*)target;
    p[0] = 0x48; p[1] = 0xB8;
    *(uint64_t*)(p + 2) = (uint64_t)hook;
    p[10] = 0xFF; p[11] = 0xE0;

    DWORD dummy;
    VirtualProtect(target, 12, old_protect, &dummy);
    FlushInstructionCache(GetCurrentProcess(), target, 12);

    LOG(THEME, "[THEME] Hooked %s at %p -> %p\n", func_name, target, hook);
    return true;
}

/* ======================================================================
   Hooked GetSysColor / GetSysColorBrush
   Replace the real user32.dll functions within this process.
   Makes push buttons, scrollbars, and other controls that call
   GetSysColor internally use our WinCE colors.
   ====================================================================== */

static DWORD WINAPI Hooked_GetSysColor(int nIndex) {
    if (g_theme_active && nIndex >= 0 && nIndex < WCE_NUM_SYSCOLORS)
        return g_wce_colors[nIndex];
    if (nIndex >= 0 && nIndex < MAX_DESKTOP_SYSCOLORS)
        return g_original_colors[nIndex];
    return 0;
}

static HBRUSH WINAPI Hooked_GetSysColorBrush(int nIndex) {
    if (g_theme_active && nIndex >= 0 && nIndex < WCE_NUM_SYSCOLORS)
        return GetThemedBrush(nIndex);
    if (nIndex >= 0 && nIndex < MAX_DESKTOP_SYSCOLORS) {
        if (!g_original_brushes[nIndex])
            g_original_brushes[nIndex] = CreateSolidBrush(g_original_colors[nIndex]);
        return g_original_brushes[nIndex];
    }
    return NULL;
}

/* ======================================================================
   Minimal Theme Subclass
   Handles WM_ERASEBKGND (window backgrounds) and WM_NCPAINT (caption).
   DefWindowProc resolves class pseudo-brushes from the kernel-side color
   table, bypassing our GetSysColor hook, so we need explicit overrides.
   ====================================================================== */

#define THEME_SUBCLASS_ID 0xCE0F0002

/* Recursion guard for NC painting */
static thread_local bool g_in_nc_paint = false;

/* Paint the themed caption bar on a top-level window (non-DWM path).
   Only paints if the window actually has a caption (WS_CAPTION). */
static void PaintThemedCaption(HWND hwnd) {
    LONG style = GetWindowLongW(hwnd, GWL_STYLE);
    if ((style & WS_CAPTION) != WS_CAPTION) return; /* no caption bar */

    HDC hdc = GetWindowDC(hwnd);
    if (!hdc) return;

    bool active = (GetForegroundWindow() == hwnd);
    COLORREF caption_color = GetThemedColor(active ? COLOR_ACTIVECAPTION : COLOR_INACTIVECAPTION);
    COLORREF text_color = GetThemedColor(active ? COLOR_CAPTIONTEXT : COLOR_INACTIVECAPTIONTEXT);

    RECT wr;
    GetWindowRect(hwnd, &wr);
    int winW = wr.right - wr.left;
    int frame = GetSystemMetrics(SM_CXFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
    int captH = GetSystemMetrics(SM_CYCAPTION);
    int border_top = GetSystemMetrics(SM_CYFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);

    RECT captRect = { frame, border_top, winW - frame, border_top + captH };

    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
    int btnW = GetSystemMetrics(SM_CXSIZE) - 2;
    int btnH = captH - 4;
    int btnY = captRect.top + 2;

    /* Fill the ENTIRE caption rect with themed color (including behind buttons).
       This overwrites the DWM-rendered blue caption. */
    HBRUSH captBrush = CreateSolidBrush(caption_color);
    FillRect(hdc, &captRect, captBrush);
    DeleteObject(captBrush);

    /* Draw caption buttons with themed face color.
       DrawFrameControl uses our hooked GetSysColor(COLOR_BTNFACE). */
    HBRUSH faceBrush = GetThemedBrush(COLOR_3DFACE);
    int btnX = captRect.right - 2;

    if (style & WS_SYSMENU) {
        btnX -= btnW;
        RECT btnR = { btnX, btnY, btnX + btnW, btnY + btnH };
        FillRect(hdc, &btnR, faceBrush);
        DrawFrameControl(hdc, &btnR, DFC_CAPTION, DFCS_CAPTIONCLOSE);
    }
    if (exStyle & WS_EX_CONTEXTHELP) {
        btnX -= btnW;
        RECT btnR = { btnX, btnY, btnX + btnW, btnY + btnH };
        FillRect(hdc, &btnR, faceBrush);
        DrawFrameControl(hdc, &btnR, DFC_CAPTION, DFCS_CAPTIONHELP);
    }
    if (style & WS_MAXIMIZEBOX) {
        btnX -= btnW;
        RECT btnR = { btnX, btnY, btnX + btnW, btnY + btnH };
        FillRect(hdc, &btnR, faceBrush);
        DrawFrameControl(hdc, &btnR, DFC_CAPTION,
            IsZoomed(hwnd) ? DFCS_CAPTIONRESTORE : DFCS_CAPTIONMAX);
    }
    if (style & WS_MINIMIZEBOX) {
        btnX -= btnW;
        RECT btnR = { btnX, btnY, btnX + btnW, btnY + btnH };
        FillRect(hdc, &btnR, faceBrush);
        DrawFrameControl(hdc, &btnR, DFC_CAPTION, DFCS_CAPTIONMIN);
    }

    /* Draw the icon */
    HICON hIcon = (HICON)GetClassLongPtrW(hwnd, GCLP_HICONSM);
    if (!hIcon) hIcon = (HICON)GetClassLongPtrW(hwnd, GCLP_HICON);
    int iconW = 0;
    if (hIcon) {
        int iconSize = GetSystemMetrics(SM_CXSMICON);
        int iconY = captRect.top + (captH - iconSize) / 2;
        DrawIconEx(hdc, captRect.left + 2, iconY, hIcon, iconSize, iconSize, 0, NULL, DI_NORMAL);
        iconW = iconSize + 4;
    }

    /* Draw caption text */
    wchar_t title[256] = {};
    GetWindowTextW(hwnd, title, 256);
    if (title[0]) {
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, text_color);

        /* Cache the caption font — SPI_GETNONCLIENTMETRICS is expensive */
        static HFONT s_captFont = NULL;
        if (!s_captFont) {
            NONCLIENTMETRICSW ncm = {};
            ncm.cbSize = sizeof(ncm);
            SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
            s_captFont = CreateFontIndirectW(&ncm.lfCaptionFont);
        }
        HFONT oldFont = (HFONT)SelectObject(hdc, s_captFont);

        RECT textRect = captRect;
        textRect.left += 4 + iconW;
        textRect.right = btnX - 4;
        DrawTextW(hdc, title, -1, &textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

        SelectObject(hdc, oldFont);
    }

    ReleaseDC(hwnd, hdc);
}

static LRESULT CALLBACK ThemeSubclassProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR subclassId, DWORD_PTR refData)
{
    bool is_toplevel = (refData != 0);

    switch (msg) {

    /* WM_CTLCOLOR*: DefWindowProc/DefDlgProc returns brushes from the kernel
       color table, bypassing our GetSysColor hook. Return themed brushes. */
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

    /* WM_ERASEBKGND: fill with themed color.
       DefWindowProc resolves pseudo-brush from the kernel color table,
       bypassing our GetSysColor hook. Override with themed brush. */
    case WM_ERASEBKGND: {
        ULONG_PTR cls_brush = GetClassLongPtrW(hwnd, GCLP_HBRBACKGROUND);
        int color_idx = COLOR_3DFACE;
        if (cls_brush >= 1 && cls_brush <= 31) {
            color_idx = (int)cls_brush - 1;
            if (color_idx >= WCE_NUM_SYSCOLORS) color_idx = COLOR_3DFACE;
        } else if (cls_brush == 0) {
            break; /* No class brush — let DefWindowProc handle */
        } else {
            break; /* Real HBRUSH handle — don't override */
        }
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, GetThemedBrush(color_idx));
        return 1;
    }

    /* WM_NCPAINT / WM_NCACTIVATE: overdraw caption with themed color.
       On DWM systems DwmSetWindowAttribute handles caption color, but on
       non-DWM systems (or when DWM ignores our color) we paint manually. */
    case WM_NCPAINT:
    case WM_NCACTIVATE:
        if (is_toplevel && !g_in_nc_paint) {
            g_in_nc_paint = true;
            LRESULT lr = DefSubclassProc(hwnd, msg, wParam, lParam);
            PaintThemedCaption(hwnd);
            g_in_nc_paint = false;
            return lr;
        }
        break;

    case WM_NCDESTROY:
        RemoveWindowSubclass(hwnd, ThemeSubclassProc, THEME_SUBCLASS_ID);
        break;
    }

    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

/* ======================================================================
   Theme Initialization
   ====================================================================== */

void Win32Thunks::InitWceTheme() {
    LOG(THEME, "[THEME] InitWceTheme: enable_theming=%d, disable_uxtheme=%d\n",
            enable_theming, disable_uxtheme);
    if (!enable_theming && !disable_uxtheme) return;

    if (enable_theming) {
        /* Cache all original desktop system colors BEFORE hooking */
        for (int i = 0; i < MAX_DESKTOP_SYSCOLORS; i++)
            g_original_colors[i] = GetSysColor(i);
        memset(g_original_brushes, 0, sizeof(g_original_brushes));

        /* Ensure registry is loaded */
        LoadRegistry();

        /* Read HKLM\SYSTEM\GWE\SysColor from emulated registry.
           Format: 27 x 4-byte COLORREFs (R,G,B,0 per entry = 108 bytes total). */
        bool loaded_from_reg = false;
        std::wstring key = L"hklm\\system\\gwe";
        auto it = registry.find(key);
        if (it != registry.end()) {
            std::wstring valname = L"syscolor";
            auto vit = it->second.values.find(valname);
            if (vit != it->second.values.end() && vit->second.type == REG_BINARY) {
                const auto& data = vit->second.data;
                size_t count = data.size() / 4;
                if (count > WCE_NUM_SYSCOLORS) count = WCE_NUM_SYSCOLORS;
                for (size_t i = 0; i < count; i++) {
                    uint8_t r = data[i * 4 + 0];
                    uint8_t g = data[i * 4 + 1];
                    uint8_t b = data[i * 4 + 2];
                    g_wce_colors[i] = RGB(r, g, b);
                }
                loaded_from_reg = true;
                LOG(THEME, "[THEME] Loaded %zu system colors from registry\n", count);
            }
        }

        if (!loaded_from_reg) {
            memcpy(g_wce_colors, wce5_default_colors, sizeof(g_wce_colors));
            LOG(THEME, "[THEME] Using default WinCE 5.0 system colors\n");

            std::vector<uint8_t> blob(WCE_NUM_SYSCOLORS * 4);
            for (int i = 0; i < WCE_NUM_SYSCOLORS; i++) {
                blob[i * 4 + 0] = GetRValue(g_wce_colors[i]);
                blob[i * 4 + 1] = GetGValue(g_wce_colors[i]);
                blob[i * 4 + 2] = GetBValue(g_wce_colors[i]);
                blob[i * 4 + 3] = 0;
            }
            RegValue val;
            val.type = REG_BINARY;
            val.data = std::move(blob);
            registry[key].values[L"syscolor"] = val;
            EnsureParentKeys(key);
            SaveRegistry();
        }

        /* Initialize brush cache */
        memset(g_wce_brushes, 0, sizeof(g_wce_brushes));

        g_theme_active = true;

        LOG(THEME, "[THEME] WinCE theming active (hook+subclass). Caption=0x%06X, BtnFace=0x%06X, Window=0x%06X\n",
            g_wce_colors[COLOR_ACTIVECAPTION],
            g_wce_colors[COLOR_BTNFACE],
            g_wce_colors[COLOR_WINDOW]);

        /* Install inline hooks on user32.dll's GetSysColor and GetSysColorBrush.
           Handles buttons, scrollbars, and other controls that call GetSysColor
           internally for their painting. */
        HMODULE user32 = GetModuleHandleA("user32.dll");
        if (user32) {
            void* pGetSysColor = (void*)GetProcAddress(user32, "GetSysColor");
            void* pGetSysColorBrush = (void*)GetProcAddress(user32, "GetSysColorBrush");

            if (pGetSysColor)
                InstallInlineHook("GetSysColor", pGetSysColor, (void*)Hooked_GetSysColor);
            if (pGetSysColorBrush)
                InstallInlineHook("GetSysColorBrush", pGetSysColorBrush, (void*)Hooked_GetSysColorBrush);
        } else {
            LOG(THEME, "[THEME] WARNING: user32.dll not found, hooks not installed\n");
        }
    }
}

/* ---- Per-window theme application ---- */

void Win32Thunks::ApplyWindowTheme(HWND hwnd, bool is_toplevel) {
    if (!hwnd) return;

    /* Strip UxTheme visual styles for classic WinCE look */
    if (disable_uxtheme) {
        SetWindowTheme(hwnd, L"", L"");
    }

    if (enable_theming) {
        /* Install subclass for WM_ERASEBKGND and WM_NCPAINT overrides */
        SetWindowSubclass(hwnd, ThemeSubclassProc, THEME_SUBCLASS_ID,
                          is_toplevel ? 1 : 0);

        /* On DWM systems, set caption color via DWM API (works on Win11+).
           The subclass WM_NCPAINT handler is a fallback for non-DWM or
           when DWM doesn't honor the color (e.g. older Win10). */
        if (is_toplevel) {
            BOOL dwm_enabled = FALSE;
            DwmIsCompositionEnabled(&dwm_enabled);
            if (dwm_enabled) {
                COLORREF caption = g_wce_colors[COLOR_ACTIVECAPTION];
                COLORREF text = g_wce_colors[COLOR_CAPTIONTEXT];
                DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &caption, sizeof(caption));
                DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &text, sizeof(text));
                LOG(THEME, "[THEME] DWM caption=0x%06X text=0x%06X for hwnd=%p\n",
                    caption, text, hwnd);
            }
        }
    }
}

/* ---- Update theme colors at runtime (called from SetSysColors thunk) ---- */

void Win32Thunks::UpdateWceThemeColor(int index, COLORREF color) {
    if (index < 0 || index >= WCE_NUM_SYSCOLORS) return;
    g_wce_colors[index] = color;
    if (g_wce_brushes[index]) {
        DeleteObject(g_wce_brushes[index]);
        g_wce_brushes[index] = nullptr;
    }
}

/* ---- Thunk-level color access (for ARM code calling GetSysColor) ---- */

COLORREF Win32Thunks::GetWceThemeColor(int index) {
    if (enable_theming && index >= 0 && index < WCE_NUM_SYSCOLORS)
        return g_wce_colors[index];
    if (index >= 0 && index < MAX_DESKTOP_SYSCOLORS)
        return g_original_colors[index];
    return 0;
}

HBRUSH Win32Thunks::GetWceThemeBrush(int index) {
    if (enable_theming && index >= 0 && index < WCE_NUM_SYSCOLORS) {
        if (!g_wce_brushes[index])
            g_wce_brushes[index] = CreateSolidBrush(g_wce_colors[index]);
        return g_wce_brushes[index];
    }
    if (index >= 0 && index < MAX_DESKTOP_SYSCOLORS) {
        if (!g_original_brushes[index])
            g_original_brushes[index] = CreateSolidBrush(g_original_colors[index]);
        return g_original_brushes[index];
    }
    return NULL;
}
