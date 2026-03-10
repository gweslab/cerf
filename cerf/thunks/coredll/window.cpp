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
        /* Class name can be a string pointer or an ATOM (MAKEINTATOM: high word=0, low word=atom).
           In WinCE 32-bit, ATOM is passed as a uint32_t where high 16 bits are 0. */
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
        bool has_captionok = (exStyle & 0x80000000) != 0;
        exStyle &= 0x0FFFFFFF;       /* strip WinCE-only high bits (including WS_EX_CAPTIONOKBTN) */
        /* WinCE COMBOBOX defaults to CBS_DROPDOWN when no CBS type bits are set.
           Desktop Windows treats type=0 as CBS_SIMPLE (list always visible).
           Force CBS_DROPDOWN so combo boxes collapse to edit-only height. */
        if (_wcsicmp(className.c_str(), L"COMBOBOX") == 0 && (style & 0x3) == 0)
            style |= CBS_DROPDOWN;
        /* WinCE allows WS_CHILD windows with NULL parent (e.g. "Menu" class).
           Desktop Windows doesn't — strip WS_CHILD when parent is NULL. */
        if (parent == NULL && (style & WS_CHILD)) {
            style &= ~(uint32_t)WS_CHILD;
            style |= WS_POPUP;
        }
        bool is_toplevel = (parent == NULL && !(style & WS_CHILD));
        bool is_popup_no_caption = is_toplevel && (style & WS_POPUP) && !(style & WS_CAPTION);
        /* Detect fullscreen-like windows: top-level with dimensions matching screen size.
           These should use WS_POPUP style with exact screen dimensions, no frame inflation.
           Examples: DesktopExplorerWindow (WS_CLIPCHILDREN|WS_CLIPSIBLINGS|WS_CAPTION, size=screen) */
        bool is_fullscreen = is_toplevel && w > 0 && h > 0 &&
            (uint32_t)w >= screen_width && (uint32_t)h >= screen_height;
        if (is_toplevel && !is_popup_no_caption && !is_fullscreen) {
            /* WinCE top-level windows always have a title bar with text.
               Ensure WS_CAPTION is set so desktop Windows draws the title text.
               (Skip for WS_POPUP windows without WS_CAPTION — e.g. desktop window) */
            style |= WS_CAPTION;
            if (x == (int)0x80000000 || y == (int)0x80000000 ||
                w == (int)0x80000000 || h == (int)0x80000000 ||
                (w == 0 && h == 0)) {
                /* CW_USEDEFAULT or zero size — go fullscreen like WinCE.
                   Inflate so that client area = screen_width x screen_height. */
                RECT fs = { 0, 0, (LONG)screen_width, (LONG)screen_height };
                AdjustWindowRectEx(&fs, style, FALSE, exStyle);
                x = fs.left; y = fs.top;
                w = fs.right - fs.left; h = fs.bottom - fs.top;
            } else {
                /* App specified explicit WinCE window dimensions (e.g. calc: 480x240).
                   On WinCE the w,h IS the total window size including thin frame
                   (1px border each side + caption).  Client area = (w-2) x (h-2-cyCaption).
                   We create a desktop window with matching client area, and thunk
                   GetWindowRect to return the original WinCE dimensions so apps
                   don't see inflated values (calc checks width<=480 for scaling). */
                int cyCaption = GetSystemMetrics(SM_CYCAPTION);
                int wince_client_w = w - 2;  /* WinCE: 1px border each side */
                int wince_client_h = h - 2 - cyCaption;
                if (wince_client_w < 1) wince_client_w = 1;
                if (wince_client_h < 1) wince_client_h = 1;
                RECT rc = { 0, 0, wince_client_w, wince_client_h };
                AdjustWindowRectEx(&rc, style, FALSE, exStyle);
                w = rc.right - rc.left;
                h = rc.bottom - rc.top;
            }
            exStyle |= WS_EX_APPWINDOW;
        } else if (is_popup_no_caption || is_fullscreen) {
            /* WS_POPUP without caption, or fullscreen window (e.g. desktop, taskbar).
               Use WS_POPUP style with exact dimensions — no frame inflation. */
            style &= ~(uint32_t)WS_CAPTION;  /* strip caption to avoid frame */
            style |= WS_POPUP;
            if (x == (int)0x80000000) x = 0;
            if (y == (int)0x80000000) y = 0;
            if (w == (int)0x80000000 || w == 0) w = (int)screen_width;
            if (h == (int)0x80000000 || h == 0) h = (int)screen_height;
        } else {
            if (x==(int)0x80000000) x=0; if (y==(int)0x80000000) y=0;
            if (w==(int)0x80000000) w=320;
            if (h==(int)0x80000000) h=240;
            /* WinCE allows w=0/h=0 for child controls (sized later by parent).
               Desktop Windows doesn't always auto-size, so use defaults — except
               for classes that explicitly need w=0 (e.g. Menu class in CommandBar). */
            bool allow_zero_size = (className == L"Menu");
            if (!allow_zero_size) {
                if (w == 0) w = 320;
                if (h == 0) h = 240;
            }
        }
        /* WinCE shell creates SysListView32 without LVS_AUTOARRANGE. The ARM commctrl
           code auto-arranges icons on WM_WINDOWPOSCHANGED only if this flag is set. */
        if (className == L"SysListView32") {
            style |= 0x0100; /* LVS_AUTOARRANGE */
        }
        LOG(API, "[API] CreateWindowExW: class='%ls' title='%ls' style=0x%08X exStyle=0x%08X parent=0x%p size=(%dx%d) lpParam=0x%08X\n", className.c_str(), windowName.c_str(), style, exStyle, parent, w, h, arm_lpParam);
        HWND hwnd = CreateWindowExW(exStyle, lpClassName, windowName.c_str(), style, x, y, w, h, parent, menu_h, GetModuleHandleW(NULL), (LPVOID)(uintptr_t)arm_lpParam);
        if (!hwnd) {
            DWORD err = GetLastError();
            WNDCLASSEXW probe = {}; probe.cbSize = sizeof(probe);
            BOOL found = GetClassInfoExW(GetModuleHandleW(NULL), lpClassName, &probe);
            BOOL foundGlobal = found ? TRUE : GetClassInfoExW(NULL, lpClassName, &probe);
            LOG(API, "[API]   CreateWindowExW FAILED (error=%d, classFound=%d/%d)\n", err, found, foundGlobal);
        }
        if (hwnd) {
            /* Case-insensitive lookup: window classes are case-insensitive */
            uint32_t arm_wndproc = 0;
            for (auto& [cls, proc] : arm_wndprocs) {
                if (_wcsicmp(cls.c_str(), className.c_str()) == 0) {
                    arm_wndproc = proc;
                    break;
                }
            }
            /* Only set if not already updated (e.g., by SetWindowLongW(GWL_WNDPROC)
               during WM_CREATE — as done by aygshell's TempWndProc pattern) */
            if (arm_wndproc && hwnd_wndproc_map.find(hwnd) == hwnd_wndproc_map.end())
                hwnd_wndproc_map[hwnd] = arm_wndproc;

            if (is_toplevel) {
                if (!windowName.empty()) SetWindowTextW(hwnd, windowName.c_str());
                HICON hIcon = LoadIconW(NULL, IDI_APPLICATION);
                SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
                SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
            }
            /* Apply WinCE theme (strip UxTheme, set title bar color).
               Must be installed BEFORE CaptionOk so the OK button subclass
               processes WM_NCPAINT first (LIFO) and paints on top of caption. */
            ApplyWindowTheme(hwnd, is_toplevel);
            if (has_captionok) {
                captionok_hwnds.insert(hwnd);
                InstallCaptionOk(hwnd);
                LOG(API, "[API]   WS_EX_CAPTIONOKBTN tracked for HWND=0x%p\n", hwnd);
            }
            /* On real WinCE, the default system font is Tahoma (from SYSFNT registry).
               On desktop Windows, native controls default to Segoe UI.
               Send WM_SETFONT with the WinCE system font to child controls so they
               match the real WinCE appearance without requiring explicit WM_SETFONT. */
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
        /* Erase wndproc map AFTER DestroyWindow so WM_DESTROY reaches ARM code */
        hwnd_dlgproc_map.erase(hw);
        BOOL ret = DestroyWindow(hw);
        LOG(API, "[API] DestroyWindow result=%d, error=%d\n", ret, GetLastError());
        hwnd_wndproc_map.erase(hw);
        regs[0] = ret;
        return true;
    });
}
