/* Window layout/query thunks: sizing, positioning, scrolling, enumeration */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <commctrl.h>

void Win32Thunks::RegisterWindowLayoutHandlers() {
    Thunk("SetWindowPos", 247, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        int swp_x = (int)regs[2], swp_y = (int)regs[3];
        int swp_cx = (int)ReadStackArg(regs,mem,0), swp_cy = (int)ReadStackArg(regs,mem,1);
        UINT swp_flags = ReadStackArg(regs,mem,2);
        /* No inflation — ARM code computes WinCE-compatible dimensions using our
           overridden GetSystemMetrics/AdjustWindowRectEx.  Windows are WS_POPUP
           with WinCE NC area handled by EmuWndProc's WM_NCCALCSIZE. */
        HWND after = (HWND)(intptr_t)(int32_t)regs[1];
        LOG(API, "[API] SetWindowPos(hwnd=0x%p, after=0x%p, x=%d, y=%d, cx=%d, cy=%d, flags=0x%X)\n",
            hw, after, swp_x, swp_y, swp_cx, swp_cy, swp_flags);
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
    Thunk("GetWindow", 251, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        UINT cmd = regs[1];
        HWND result = GetWindow(hw, cmd);
        /* For sibling enumeration (GW_HWNDNEXT=2, GW_HWNDPREV=3, GW_HWNDFIRST=0,
           GW_HWNDLAST=1), skip windows not owned by cerf.  This prevents the taskbar
           from showing native host windows (IDA, etc.) as running apps. */
        if (cmd <= 3) {
            DWORD our_pid = GetCurrentProcessId();
            while (result) {
                DWORD pid = 0;
                GetWindowThreadProcessId(result, &pid);
                if (pid == our_pid) break;
                result = GetWindow(result, (cmd == 0 || cmd == 2) ? GW_HWNDNEXT : GW_HWNDPREV);
            }
        }
        regs[0] = (uint32_t)(uintptr_t)result;
        return true;
    });
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
        /* No frame correction needed — windows are WS_POPUP with WinCE NC area
           handled by our WM_NCCALCSIZE, so native coordinates are correct. */
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
        uint32_t wndproc = regs[0];
        HWND hw = (HWND)(intptr_t)(int32_t)regs[1];
        UINT umsg = regs[2]; WPARAM wp = regs[3]; LPARAM lp = ReadStackArg(regs, mem, 0);
        /* If the wndproc is an ARM address (in emulated memory), call via callback_executor */
        if (wndproc && wndproc < 0x20000000 && mem.IsValid(wndproc) && callback_executor) {
            uint32_t args[4] = { (uint32_t)(uintptr_t)hw, umsg, (uint32_t)wp, (uint32_t)lp };
            regs[0] = callback_executor(wndproc, args, 4);
        } else {
            regs[0] = (uint32_t)DefWindowProcW(hw, umsg, wp, lp);
        }
        return true;
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
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        POINT pt; pt.x = mem.Read32(regs[1]); pt.y = mem.Read32(regs[1]+4);
        BOOL ret = ClientToScreen(hw, &pt);
        mem.Write32(regs[1], pt.x); mem.Write32(regs[1]+4, pt.y);
        regs[0] = ret; return true;
    });
    Thunk("ScreenToClient", 255, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        POINT pt; pt.x = mem.Read32(regs[1]); pt.y = mem.Read32(regs[1]+4);
        BOOL ret = ScreenToClient(hw, &pt);
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
    /* DeferWindowPos — pass through to native */
    Thunk("BeginDeferWindowPos", 1157, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)BeginDeferWindowPos(regs[0]); return true;
    });
    Thunk("DeferWindowPos", 1158, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDWP hdwp = (HDWP)(intptr_t)(int32_t)regs[0];
        HWND hwnd = (HWND)(intptr_t)(int32_t)regs[1];
        HWND after = (HWND)(intptr_t)(int32_t)regs[2];
        int x = (int)regs[3], y = (int)ReadStackArg(regs,mem,0);
        int cx = (int)ReadStackArg(regs,mem,1), cy = (int)ReadStackArg(regs,mem,2);
        UINT flags = ReadStackArg(regs,mem,3);
        regs[0] = (uint32_t)(uintptr_t)DeferWindowPos(hdwp, hwnd, after, x, y, cx, cy, flags);
        return true;
    });
    Thunk("EndDeferWindowPos", 1159, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = EndDeferWindowPos((HDWP)(intptr_t)(int32_t)regs[0]); return true;
    });
}
