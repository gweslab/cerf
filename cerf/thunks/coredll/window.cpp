/* Window thunks: RegisterClass, CreateWindowEx, Show/Move/Destroy */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <commctrl.h>

void Win32Thunks::RegisterWindowHandlers() {
    Thunk("RegisterClassW", 95, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t arm_wndproc = mem.Read32(regs[0] + 4);
        WNDCLASSW wc = {};
        wc.style = mem.Read32(regs[0]); wc.lpfnWndProc = EmuWndProc;
        wc.cbClsExtra = mem.Read32(regs[0]+8); wc.cbWndExtra = mem.Read32(regs[0]+12);
        wc.hInstance = GetModuleHandleW(NULL);
        /* WinCE icon/cursor/brush handles are 32-bit values that don't map to
           native x64 GDI handles. Use safe native equivalents instead.
           The ARM WndProc handles all actual drawing via EmuWndProc dispatch. */
        uint32_t emu_cursor = mem.Read32(regs[0]+24);
        uint32_t emu_brush = mem.Read32(regs[0]+28);
        wc.hIcon = NULL;
        wc.hCursor = emu_cursor ? LoadCursorW(NULL, IDC_ARROW) : NULL;
        /* Brush values 1-31 are COLOR_xxx+1 constants — pass through directly.
           WinCE GetSysColor uses a 0x40000000 flag on color indices; strip it.
           Non-zero values above 31 are native GDI brush handles (truncated to
           32-bit by our GetSysColorBrush/CreateSolidBrush thunks) — sign-extend
           them back to 64-bit so DefWindowProc can use them for WM_ERASEBKGND. */
        uint32_t brush_val = emu_brush & 0x3FFFFFFF; /* strip WinCE sys color flag */
        if (brush_val > 0 && brush_val <= 31) {
            /* Brush values 1-31 encode COLOR_xxx+1.  WinCE added COLOR_STATIC=25
               and COLOR_STATICTEXT=26 which don't exist on desktop Windows.
               Map them to appropriate desktop equivalents. */
            if (brush_val == 26)      brush_val = COLOR_3DFACE + 1;     /* COLOR_STATIC+1 */
            else if (brush_val == 27) brush_val = COLOR_WINDOWTEXT + 1; /* COLOR_STATICTEXT+1 */
            wc.hbrBackground = (HBRUSH)(uintptr_t)brush_val;
        }
        else if (emu_brush != 0)
            wc.hbrBackground = (HBRUSH)(intptr_t)(int32_t)emu_brush;
        else
            wc.hbrBackground = NULL;
        std::wstring className = ReadWStringFromEmu(mem, mem.Read32(regs[0]+36));
        wc.lpszClassName = className.c_str();
        arm_wndprocs[className] = arm_wndproc;
        LOG(API, "[API] RegisterClassW: '%ls' (ARM WndProc=0x%08X, brush=0x%08X->0x%08X)\n",
            className.c_str(), arm_wndproc, emu_brush, (uint32_t)(uintptr_t)wc.hbrBackground);
        ATOM atom = RegisterClassW(&wc);
        if (!atom && GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
            /* The native comctl32.dll (or another system DLL) already registered
               this class with a native WndProc.  We must replace it with our
               EmuWndProc so that ARM code controls the window.  Try unregistering
               the existing class from known system DLL hInstances, then re-register. */
            LOG(API, "[API]   Class '%ls' already exists, replacing with ARM version\n", className.c_str());
            HMODULE mods[] = {
                GetModuleHandleW(L"comctl32.dll"),
                GetModuleHandleW(L"comctl32"),
                GetModuleHandleW(NULL),
                NULL
            };
            for (HMODULE mod : mods) {
                if (mod && UnregisterClassW(className.c_str(), mod)) {
                    LOG(API, "[API]   Unregistered existing class from module %p\n", mod);
                    break;
                }
            }
            atom = RegisterClassW(&wc);
        }
        if (!atom) LOG(API, "[API]   RegisterClassW FAILED (error=%d)\n", GetLastError());
        regs[0] = (uint32_t)atom; return true;
    });
    Thunk("CreateWindowExW", 246, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t exStyle = regs[0];
        uint32_t class_raw = regs[1];
        bool class_is_atom = (class_raw != 0 && class_raw <= 0xFFFF);
        std::wstring className;
        LPCWSTR lpClassName;
        if (class_is_atom) {
            lpClassName = MAKEINTRESOURCEW(class_raw);
            wchar_t buf[32];
            swprintf(buf, 32, L"#ATOM:%u", class_raw);
            className = buf;
        } else {
            className = ReadWStringFromEmu(mem, class_raw);
            lpClassName = className.c_str();
        }
        std::wstring windowName = ReadWStringFromEmu(mem, regs[2]);
        uint32_t style = regs[3];
        int x=(int)ReadStackArg(regs,mem,0), y=(int)ReadStackArg(regs,mem,1);
        int w=(int)ReadStackArg(regs,mem,2), h=(int)ReadStackArg(regs,mem,3);
        HWND parent = (HWND)(intptr_t)(int32_t)ReadStackArg(regs,mem,4);
        HMENU menu_h = (HMENU)(intptr_t)(int32_t)ReadStackArg(regs,mem,5);
        uint32_t arm_lpParam = ReadStackArg(regs,mem,7);

        /* Save original WinCE styles before any modification */
        uint32_t wce_style = style;
        uint32_t wce_exstyle = exStyle;
        bool has_captionok = (exStyle & 0x80000000) != 0;
        exStyle &= 0x0FFFFFFF; /* strip WinCE-only high bits */

        /* WinCE COMBOBOX defaults to CBS_DROPDOWN when no CBS type bits are set */
        if (_wcsicmp(className.c_str(), L"COMBOBOX") == 0 && (style & 0x3) == 0)
            style |= CBS_DROPDOWN;
        /* WinCE allows WS_CHILD with NULL parent — desktop doesn't */
        if (parent == NULL && (style & WS_CHILD)) {
            style &= ~(uint32_t)WS_CHILD;
            style |= WS_POPUP;
        }

        bool is_child = (style & WS_CHILD) != 0;
        bool is_toplevel = (parent == NULL && !is_child);

        LOG(API, "[API] CWEx: class='%ls' wce_style=0x%08X exStyle=0x%08X toplevel=%d w=%d h=%d\n",
            className.c_str(), wce_style, wce_exstyle, is_toplevel, w, h);

        if (is_toplevel) {
            bool has_caption = (wce_style & WS_CAPTION) == WS_CAPTION;

            /* Convert all top-level WinCE windows to WS_POPUP on desktop.
               This eliminates the native thick frame entirely — no inflate/deflate.
               Our WM_NCCALCSIZE handler in EmuWndProc provides WinCE NC area. */
            style &= ~(uint32_t)(WS_OVERLAPPED | WS_THICKFRAME |
                                  WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_CAPTION);
            style |= WS_POPUP;
            exStyle |= WS_EX_APPWINDOW;

            /* CW_USEDEFAULT (0x80000000) → WinCE defaults to fullscreen at (0,0) */
            if (x == (int)0x80000000) x = 0;
            if (y == (int)0x80000000) y = 0;

            if (w == (int)0x80000000 || w == 0) {
                /* CW_USEDEFAULT or zero size → fullscreen */
                if (has_caption) {
                    int cyCaption = GetSystemMetrics(SM_CYCAPTION);
                    w = (int)screen_width + 2;              /* 1px border each side */
                    h = (int)screen_height + 2 + cyCaption; /* + caption bar */
                } else {
                    w = (int)screen_width;
                    h = (int)screen_height;
                }
            } else if (h == (int)0x80000000 || h == 0) {
                h = has_caption ? (int)screen_height + 2 + GetSystemMetrics(SM_CYCAPTION)
                                : (int)screen_height;
            }
            /* Dimensions pass through as-is — ARM code already computed them
               using our WinCE-compatible GetSystemMetrics/AdjustWindowRectEx. */
        } else if (!is_child) {
            /* Owned popup (has parent but not WS_CHILD) — convert to WS_POPUP
               just like top-level windows for consistent WinCE NC area handling. */
            style &= ~(uint32_t)(WS_OVERLAPPED | WS_THICKFRAME |
                                  WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_CAPTION);
            style |= WS_POPUP;
            if (x == (int)0x80000000) x = 0;
            if (y == (int)0x80000000) y = 0;
            if (w == (int)0x80000000) w = (int)screen_width;
            if (h == (int)0x80000000) h = (int)screen_height;
        } else {
            /* Child window — pass through, minimal fixups */
            if (x == (int)0x80000000) x = 0;
            if (y == (int)0x80000000) y = 0;
            bool allow_zero_size = (className == L"Menu");
            if (!allow_zero_size) {
                if (w == (int)0x80000000 || w == 0) w = (int)screen_width;
                if (h == (int)0x80000000 || h == 0) h = (int)screen_height;
            } else {
                if (w == (int)0x80000000) w = 0;
                if (h == (int)0x80000000) h = 0;
            }
        }

        /* Per-class fixups */
        if (className == L"SysListView32")
            style |= 0x0100 | 0x0800; /* LVS_AUTOARRANGE | LVS_ALIGNLEFT */
        if (className == L"Shell Embedding" || className == L"DefShellView")
            style |= WS_VISIBLE;

        LOG(API, "[API] CreateWindowExW: class='%ls' title='%ls' style=0x%08X exStyle=0x%08X parent=0x%p pos=(%d,%d) size=(%dx%d)\n",
            className.c_str(), windowName.c_str(), style, exStyle, parent, x, y, w, h);

        /* Stash original WinCE styles for EmuWndProc to pick up during WM_NCCREATE.
           Covers both true top-level and owned popup windows. */
        if (!is_child) {
            tls_pending_wce_style = wce_style;
            tls_pending_wce_exstyle = wce_exstyle;
        }

        HWND hwnd = CreateWindowExW(exStyle, lpClassName, windowName.c_str(),
            style, x, y, w, h, parent, menu_h,
            GetModuleHandleW(NULL), (LPVOID)(uintptr_t)arm_lpParam);

        tls_pending_wce_style = 0;
        tls_pending_wce_exstyle = 0;

        if (!hwnd) {
            DWORD err = GetLastError();
            LOG(API, "[API]   CreateWindowExW FAILED (error=%d)\n", err);
        }
        if (hwnd) {
            uint32_t arm_wndproc = 0;
            for (auto& [cls, proc] : arm_wndprocs) {
                if (_wcsicmp(cls.c_str(), className.c_str()) == 0) {
                    arm_wndproc = proc;
                    break;
                }
            }
            if (arm_wndproc && hwnd_wndproc_map.find(hwnd) == hwnd_wndproc_map.end())
                hwnd_wndproc_map[hwnd] = arm_wndproc;

            if (is_toplevel) {
                if (!windowName.empty()) SetWindowTextW(hwnd, windowName.c_str());
                HICON hIcon = LoadIconW(NULL, IDI_APPLICATION);
                SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
                SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
            }
            ApplyWindowTheme(hwnd, !is_child);
            if (has_captionok) {
                captionok_hwnds.insert(hwnd);
                InstallCaptionOk(hwnd);
                LOG(API, "[API]   WS_EX_CAPTIONOKBTN tracked for HWND=0x%p\n", hwnd);
            }
            if (!is_toplevel) {
                static HFONT s_wce_default_font = NULL;
                if (!s_wce_default_font) {
                    LOGFONTW lf = {};
                    lf.lfHeight = wce_sysfont_height;
                    lf.lfWeight = wce_sysfont_weight;
                    lf.lfCharSet = DEFAULT_CHARSET;
                    lf.lfQuality = DEFAULT_QUALITY;
                    lf.lfPitchAndFamily = VARIABLE_PITCH | FF_SWISS;
                    wcscpy_s(lf.lfFaceName, wce_sysfont_name.c_str());
                    s_wce_default_font = CreateFontIndirectW(&lf);
                }
                if (s_wce_default_font)
                    ::SendMessageW(hwnd, WM_SETFONT, (WPARAM)s_wce_default_font, FALSE);
            }
        }
        regs[0] = (uint32_t)(uintptr_t)hwnd; return true;
    });
    Thunk("ShowWindow", 266, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        LOG(API, "[API] ShowWindow(0x%p, %d)\n", hw, regs[1]);
        if (hw == NULL && regs[1] == 5) { regs[0] = 0; return true; }
        regs[0] = ShowWindow(hw, regs[1]);
        /* With real threading, normal message delivery works correctly. */
        return true;
    });
    Thunk("UpdateWindow", 267, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        LOG(API, "[API] UpdateWindow(0x%p)\n", hw);
        regs[0] = UpdateWindow(hw);
        return true;
    });
    Thunk("RedrawWindow", 1672, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        /* lprcUpdate (regs[1]) — WinCE RECT ptr in emulated memory */
        RECT rc, *prc = NULL;
        if (regs[1]) { rc = {(LONG)mem.Read32(regs[1]),(LONG)mem.Read32(regs[1]+4),(LONG)mem.Read32(regs[1]+8),(LONG)mem.Read32(regs[1]+12)}; prc = &rc; }
        /* hrgnUpdate (regs[2]) — pass through as handle */
        HRGN hrgn = (HRGN)(intptr_t)(int32_t)regs[2];
        UINT flags = regs[3];
        regs[0] = RedrawWindow(hw, prc, hrgn, flags);
        return true;
    });
    Thunk("DestroyWindow", 265, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        LOG(API, "[API] DestroyWindow(0x%p) IsWindow=%d\n", hw, IsWindow(hw));
        if (captionok_hwnds.erase(hw)) RemoveCaptionOk(hw);
        hwnd_dlgproc_map.erase(hw);
        BOOL ret = DestroyWindow(hw);
        LOG(API, "[API] DestroyWindow result=%d, error=%d\n", ret, GetLastError());
        hwnd_wndproc_map.erase(hw);
        hwnd_wce_style_map.erase(hw);
        hwnd_wce_exstyle_map.erase(hw);
        regs[0] = ret;
        return true;
    });
}
