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
        if (!atom) LOG(API, "[API]   RegisterClassW FAILED (error=%d)\n", GetLastError());
        regs[0] = (uint32_t)atom; return true;
    });
    Thunk("CreateWindowExW", 246, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t exStyle = regs[0];
        std::wstring className = ReadWStringFromEmu(mem, regs[1]);
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
        if (is_toplevel) {
            /* WinCE top-level windows always have a title bar with text.
               Ensure WS_CAPTION is set so desktop Windows draws the title text. */
            style |= WS_CAPTION;
            RECT wa; SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
            int bw = GetSystemMetrics(SM_CXBORDER), bh = GetSystemMetrics(SM_CYBORDER);
            x = wa.left-bw; y = wa.top-bh;
            w = (wa.right-wa.left)+bw*2; h = (wa.bottom-wa.top)+bh*2;
            exStyle |= WS_EX_APPWINDOW;
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
        LOG(API, "[API] CreateWindowExW: class='%ls' title='%ls' style=0x%08X exStyle=0x%08X parent=0x%p size=(%dx%d) lpParam=0x%08X\n", className.c_str(), windowName.c_str(), style, exStyle, parent, w, h, arm_lpParam);
        HWND hwnd = CreateWindowExW(exStyle, className.c_str(), windowName.c_str(), style, x, y, w, h, parent, menu_h, GetModuleHandleW(NULL), (LPVOID)(uintptr_t)arm_lpParam);
        if (!hwnd) {
            DWORD err = GetLastError();
            WNDCLASSEXW probe = {}; probe.cbSize = sizeof(probe);
            BOOL found = GetClassInfoExW(GetModuleHandleW(NULL), className.c_str(), &probe);
            BOOL foundGlobal = found ? TRUE : GetClassInfoExW(NULL, className.c_str(), &probe);
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
            if (arm_wndproc) hwnd_wndproc_map[hwnd] = arm_wndproc;
            if (is_toplevel) {
                if (!windowName.empty()) SetWindowTextW(hwnd, windowName.c_str());
                HICON hIcon = LoadIconW(NULL, IDI_APPLICATION);
                SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
                SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
            }
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
    Thunk("ShowWindow", 266, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        if (hw == NULL && regs[1] == 5) { regs[0] = 0; return true; }
        regs[0] = ShowWindow(hw, regs[1]);
        return true;
    });
    Thunk("UpdateWindow", 267, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = UpdateWindow((HWND)(intptr_t)(int32_t)regs[0]); return true; });
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
        if (captionok_hwnds.erase(hw)) RemoveCaptionOk(hw);
        hwnd_wndproc_map.erase(hw);
        hwnd_dlgproc_map.erase(hw);
        regs[0] = DestroyWindow(hw);
        return true;
    });
    Thunk("SetWindowPos", 247, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        int swp_x = (int)regs[2], swp_y = (int)regs[3];
        int swp_cx = (int)ReadStackArg(regs,mem,0), swp_cy = (int)ReadStackArg(regs,mem,1);
        UINT swp_flags = ReadStackArg(regs,mem,2);
        LOG(API, "[API] SetWindowPos(hwnd=0x%p, x=%d, y=%d, cx=%d, cy=%d, flags=0x%X)\n",
            hw, swp_x, swp_y, swp_cx, swp_cy, swp_flags);
        regs[0] = SetWindowPos(hw, (HWND)(intptr_t)(int32_t)regs[1], swp_x, swp_y, swp_cx, swp_cy, swp_flags);
        return true;
    });
    Thunk("MoveWindow", 272, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        int mw_x = (int)regs[1], mw_y = (int)regs[2], mw_w = (int)regs[3];
        int mw_h = (int)ReadStackArg(regs,mem,0); BOOL mw_rep = ReadStackArg(regs,mem,1);
        LOG(API, "[API] MoveWindow(hwnd=0x%p, x=%d, y=%d, w=%d, h=%d)\n", hw, mw_x, mw_y, mw_w, mw_h);
        regs[0] = MoveWindow(hw, mw_x, mw_y, mw_w, mw_h, mw_rep);
        return true;
    });
    Thunk("BringWindowToTop", 275, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = BringWindowToTop((HWND)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("GetWindow", 251, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)(uintptr_t)GetWindow((HWND)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("SetParent", 268, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = (uint32_t)(uintptr_t)SetParent((HWND)(intptr_t)(int32_t)regs[0], (HWND)(intptr_t)(int32_t)regs[1]); return true; });
    Thunk("MapWindowPoints", 284, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hwndFrom = (HWND)(intptr_t)(int32_t)regs[0];
        HWND hwndTo   = (HWND)(intptr_t)(int32_t)regs[1];
        uint32_t lpPts = regs[2];
        UINT cPoints  = regs[3];
        if (!lpPts || cPoints == 0) { regs[0] = 0; return true; }
        if (cPoints > 1024) cPoints = 1024;
        std::vector<POINT> pts(cPoints);
        for (UINT i = 0; i < cPoints; i++) {
            pts[i].x = (LONG)mem.Read32(lpPts + i * 8);
            pts[i].y = (LONG)mem.Read32(lpPts + i * 8 + 4);
        }
        int ret = MapWindowPoints(hwndFrom, hwndTo, pts.data(), cPoints);
        for (UINT i = 0; i < cPoints; i++) {
            mem.Write32(lpPts + i * 8,     (uint32_t)pts[i].x);
            mem.Write32(lpPts + i * 8 + 4, (uint32_t)pts[i].y);
        }
        regs[0] = (uint32_t)ret;
        return true;
    });
    /* GetClassInfoW — return basic info for ARM-registered classes, or native lookup */
    Thunk("GetClassInfoW", 878, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring className = ReadWStringFromEmu(mem, regs[1]);
        uint32_t pWC = regs[2];
        LOG(API, "[API] GetClassInfoW(0x%08X, '%ls', 0x%08X)\n", regs[0], className.c_str(), pWC);
        /* Check ARM-registered classes first (case-insensitive) */
        for (auto& [cls, proc] : arm_wndprocs) {
            if (_wcsicmp(cls.c_str(), className.c_str()) == 0) {
                WNDCLASSEXW wcx = {}; wcx.cbSize = sizeof(wcx);
                GetClassInfoExW(GetModuleHandleW(NULL), className.c_str(), &wcx);
                if (pWC) {
                    mem.Write32(pWC + 0,  wcx.style);
                    mem.Write32(pWC + 4,  proc);
                    mem.Write32(pWC + 8,  wcx.cbClsExtra);
                    mem.Write32(pWC + 12, wcx.cbWndExtra);
                    mem.Write32(pWC + 16, emu_hinstance);
                    mem.Write32(pWC + 20, 0);
                    mem.Write32(pWC + 24, 0);
                    mem.Write32(pWC + 28, (uint32_t)(uintptr_t)wcx.hbrBackground);
                    mem.Write32(pWC + 32, 0);
                    mem.Write32(pWC + 36, regs[1]);
                }
                LOG(API, "[API]   -> found in ARM map (proc=0x%08X)\n", proc);
                regs[0] = 1;
                return true;
            }
        }
        /* Do NOT fall back to native class lookup — native classes like
           ToolbarWindow32 exist in our process (from comctl32.lib) but have native
           WndProcs. Returning success would make ARM code skip RegisterClassW,
           creating native windows instead of ARM-controlled ones. */
        LOG(API, "[API]   -> not found\n");
        regs[0] = 0;
        return true;
    });
    Thunk("GetClassNameW", 283, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        wchar_t buf[256] = {};
        int len = GetClassNameW((HWND)(intptr_t)(int32_t)regs[0], buf, 256);
        uint32_t dst = regs[1], max_count = regs[2];
        uint32_t copy_len = (uint32_t)len < max_count - 1 ? (uint32_t)len : max_count - 1;
        for (uint32_t i = 0; i < copy_len; i++)
            mem.Write16(dst + i * 2, buf[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = len;
        return true;
    });
    Thunk("UnregisterClassW", 884, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("CallWindowProcW", 285, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)DefWindowProcW((HWND)(intptr_t)(int32_t)regs[1], regs[2], regs[3], ReadStackArg(regs,mem,0)); return true;
    });
    Thunk("ScrollWindowEx", 289, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        int dx = (int)regs[1], dy = (int)regs[2];
        RECT rcScroll, rcClip, rcUpdate;
        RECT *pScroll = NULL, *pClip = NULL, *pUpdate = NULL;
        if (regs[3]) {
            rcScroll.left=mem.Read32(regs[3]); rcScroll.top=mem.Read32(regs[3]+4);
            rcScroll.right=mem.Read32(regs[3]+8); rcScroll.bottom=mem.Read32(regs[3]+12);
            pScroll = &rcScroll;
        }
        uint32_t a4 = ReadStackArg(regs,mem,0); /* prcClip */
        uint32_t a5 = ReadStackArg(regs,mem,1); /* hrgnUpdate */
        uint32_t a6 = ReadStackArg(regs,mem,2); /* prcUpdate */
        uint32_t a7 = ReadStackArg(regs,mem,3); /* flags */
        if (a4) {
            rcClip.left=mem.Read32(a4); rcClip.top=mem.Read32(a4+4);
            rcClip.right=mem.Read32(a4+8); rcClip.bottom=mem.Read32(a4+12);
            pClip = &rcClip;
        }
        if (a6) pUpdate = &rcUpdate;
        regs[0] = ScrollWindowEx(hw, dx, dy, pScroll, pClip, (HRGN)(uintptr_t)a5, pUpdate, a7);
        if (a6 && pUpdate) {
            mem.Write32(a6, rcUpdate.left); mem.Write32(a6+4, rcUpdate.top);
            mem.Write32(a6+8, rcUpdate.right); mem.Write32(a6+12, rcUpdate.bottom);
        }
        return true;
    });
    Thunk("SetScrollInfo", 279, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        int nBar = (int)regs[1];
        SCROLLINFO si = {}; si.cbSize = sizeof(si);
        if (regs[2]) {
            si.fMask = mem.Read32(regs[2]+4); si.nMin = mem.Read32(regs[2]+8);
            si.nMax = mem.Read32(regs[2]+12); si.nPage = mem.Read32(regs[2]+16);
            si.nPos = mem.Read32(regs[2]+20);
        }
        regs[0] = SetScrollInfo(hw, nBar, &si, regs[3]);
        return true;
    });
    Thunk("GetScrollInfo", 282, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        int nBar = (int)regs[1];
        SCROLLINFO si = {}; si.cbSize = sizeof(si);
        if (regs[2]) si.fMask = mem.Read32(regs[2]+4);
        BOOL ret = GetScrollInfo(hw, nBar, &si);
        if (regs[2] && ret) {
            mem.Write32(regs[2]+8, si.nMin); mem.Write32(regs[2]+12, si.nMax);
            mem.Write32(regs[2]+16, si.nPage); mem.Write32(regs[2]+20, si.nPos);
            mem.Write32(regs[2]+24, si.nTrackPos);
        }
        regs[0] = ret;
        return true;
    });
    Thunk("SetScrollPos", 280, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SetScrollPos((HWND)(intptr_t)(int32_t)regs[0], (int)regs[1], (int)regs[2], regs[3]);
        return true;
    });
    Thunk("SetScrollRange", 281, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        regs[0] = SetScrollRange(hw, (int)regs[1], (int)regs[2], (int)regs[3], 0);
        return true;
    });
    Thunk("EnumWindows", 291, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    thunk_handlers["GetWindowThreadProcessId"] = thunk_handlers["EnumWindows"];
    Thunk("RegisterWindowMessageW", 891, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring msg_name = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = RegisterWindowMessageW(msg_name.c_str()); return true;
    });
    Thunk("GetDesktopWindow", 1397, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=(uint32_t)(uintptr_t)GetDesktopWindow(); return true; });
    Thunk("FindWindowW", 286, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring cn = ReadWStringFromEmu(mem, regs[0]), wn = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)(uintptr_t)FindWindowW(regs[0] ? cn.c_str() : NULL, regs[1] ? wn.c_str() : NULL);
        return true;
    });
    Thunk("WindowFromPoint", 252, [](uint32_t* regs, EmulatedMemory&) -> bool {
        POINT pt = { (LONG)regs[0], (LONG)regs[1] };
        regs[0] = (uint32_t)(uintptr_t)WindowFromPoint(pt); return true;
    });
    Thunk("ClientToScreen", 254, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        POINT pt; pt.x = mem.Read32(regs[1]); pt.y = mem.Read32(regs[1]+4);
        BOOL ret = ClientToScreen((HWND)(intptr_t)(int32_t)regs[0], &pt);
        mem.Write32(regs[1], pt.x); mem.Write32(regs[1]+4, pt.y);
        regs[0] = ret; return true;
    });
    Thunk("ScreenToClient", 255, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        POINT pt; pt.x = mem.Read32(regs[1]); pt.y = mem.Read32(regs[1]+4);
        BOOL ret = ScreenToClient((HWND)(intptr_t)(int32_t)regs[0], &pt);
        mem.Write32(regs[1], pt.x); mem.Write32(regs[1]+4, pt.y);
        regs[0] = ret; return true;
    });
    Thunk("ChildWindowFromPoint", 253, [](uint32_t* regs, EmulatedMemory&) -> bool {
        POINT pt; pt.x = (int32_t)regs[1]; pt.y = (int32_t)regs[2];
        regs[0] = (uint32_t)(uintptr_t)ChildWindowFromPoint((HWND)(intptr_t)(int32_t)regs[0], pt);
        return true;
    });
    /* Caret functions (659, 662, 663 — 658/660/661 registered in misc.cpp) */
    Thunk("DestroyCaret", 659, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DestroyCaret(); return true;
    });
    Thunk("SetCaretPos", 662, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SetCaretPos(regs[0], regs[1]); return true;
    });
    Thunk("GetCaretPos", 663, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        POINT pt;
        BOOL ret = GetCaretPos(&pt);
        if (regs[0]) { mem.Write32(regs[0], (uint32_t)pt.x); mem.Write32(regs[0]+4, (uint32_t)pt.y); }
        regs[0] = ret; return true;
    });
    Thunk("IsWindowVisible", 886, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = IsWindowVisible((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
}
