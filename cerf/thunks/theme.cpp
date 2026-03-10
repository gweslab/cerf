/* WinCE Theme Engine — colors, hooks, initialization, per-window apply.
   Loads system colors from the WinCE registry (HKLM\SYSTEM\GWE\SysColor)
   and applies them per-process. Zero global side effects.

   Hybrid approach:
   1. Inline-hook GetSysColor/GetSysColorBrush in user32.dll (copy-on-write).
      This makes controls that call GetSysColor internally (push buttons,
      scrollbars, etc.) use our WinCE colors automatically.
   2. Minimal window subclass (ThemeSubclassProc in theme_subclass.cpp) for
      things the hooks can't reach: WM_ERASEBKGND, WM_CTLCOLOR*, WM_NCPAINT.
   3. SetWindowTheme strips UxTheme per-window for classic WinCE look.
   No SetSysColors, no global changes. */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "theme_internal.h"
#include "../log.h"
#include <uxtheme.h>
#include <dwmapi.h>
#pragma comment(lib, "uxtheme")
#pragma comment(lib, "comctl32")
#pragma comment(lib, "dwmapi")

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
   Themed Brush / Color Helpers (used by theme_subclass.cpp via header)
   ====================================================================== */

HBRUSH GetThemedBrush(int color_idx) {
    if (color_idx < 0 || color_idx >= WCE_NUM_SYSCOLORS) return NULL;
    if (!g_wce_brushes[color_idx])
        g_wce_brushes[color_idx] = CreateSolidBrush(g_wce_colors[color_idx]);
    return g_wce_brushes[color_idx];
}

COLORREF GetThemedColor(int color_idx) {
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

        /* Install inline hooks on user32.dll's GetSysColor and GetSysColorBrush. */
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

    if (disable_uxtheme) {
        SetWindowTheme(hwnd, L"", L"");
    }

    if (enable_theming) {
        SetWindowSubclass(hwnd, ThemeSubclassProc, THEME_SUBCLASS_ID,
                          is_toplevel ? 1 : 0);
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
