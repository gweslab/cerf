/* System thunks: GetSystemMetrics, time, colors, error handling */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <algorithm>

void Win32Thunks::RegisterSystemHandlers() {
    Thunk("GetLastError", 516, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetLastError(); return true;
    });
    Thunk("SetLastError", 517, [](uint32_t* regs, EmulatedMemory&) -> bool {
        SetLastError(regs[0]); return true;
    });
    Thunk("RaiseException", 543, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t code = regs[0], flags = regs[1];
        LOG(API, "[API] RaiseException(0x%08X, flags=0x%X, nArgs=%u) from LR=0x%08X\n",
            code, flags, regs[2], regs[14]);
        /* For non-continuable exceptions, try longjmp to the most recent setjmp buffer.
           This emulates SEH __except recovery for code that uses setjmp/longjmp (like MFC). */
        if ((flags & 1) && !setjmp_stack.empty()) { /* EXCEPTION_NONCONTINUABLE */
            uint32_t buf = setjmp_stack.back();
            setjmp_stack.pop_back();
            for (int i = 4; i <= 11; i++) regs[i] = mem.Read32(buf + (i - 4) * 4);
            regs[13] = mem.Read32(buf + 8 * 4); /* SP */
            regs[14] = mem.Read32(buf + 9 * 4); /* LR */
            regs[0] = 1; /* setjmp returns non-zero on longjmp */
            LOG(API, "[API]   -> longjmp to buf=0x%08X, LR=0x%08X (recovery)\n", buf, regs[14]);
        } else {
            LOG(API, "[API]   -> ignoring (continuable or no setjmp buffer)\n");
        }
        return true;
    });
    Thunk("GetSystemMetrics", 885, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        int idx = (int)regs[0];
        /* Return WinCE-compatible screen dimensions so ARM apps see a
           reasonable screen size rather than the desktop's full resolution.
           Only override when fake_screen_resolution is enabled. */
        if (fake_screen_resolution) {
            if (idx == SM_CXSCREEN || idx == SM_CXFULLSCREEN || idx == SM_CXMAXIMIZED ||
                idx == SM_CXVIRTUALSCREEN /* 78 */) {
                regs[0] = screen_width;
                LOG(API, "[API] GetSystemMetrics(%d) -> %d (screen_width)\n", idx, regs[0]);
                return true;
            }
            if (idx == SM_CYSCREEN || idx == SM_CYFULLSCREEN || idx == SM_CYMAXIMIZED ||
                idx == SM_CYVIRTUALSCREEN /* 79 */) {
                regs[0] = screen_height;
                LOG(API, "[API] GetSystemMetrics(%d) -> %d (screen_height)\n", idx, regs[0]);
                return true;
            }
            /* Virtual screen origin — WinCE has a single monitor at (0,0) */
            if (idx == SM_XVIRTUALSCREEN || idx == SM_YVIRTUALSCREEN) {
                regs[0] = 0;
                return true;
            }
        }
        /* WinCE uses 1px borders/edges everywhere — override all frame-related
           metrics so ARM code computes WinCE-compatible window sizes.
           Our CreateWindowExW/MoveWindow/SetWindowPos inflation thunks assume
           ARM code uses 1px borders (subtracting 2 total).  If ARM code sees
           native SM_CXDLGFRAME=3 or SM_CXFRAME=4, it computes oversized window
           dimensions, causing extra space in the client area after inflation. */
        if (idx == SM_CXEDGE || idx == SM_CYEDGE) { regs[0] = 1; return true; }
        /* SM_CXBORDER(5)/SM_CYBORDER(6) are already 1 on desktop — no override needed */
        if (idx == SM_CXDLGFRAME || idx == SM_CYDLGFRAME) { regs[0] = 1; return true; }
        if (idx == SM_CXFRAME || idx == SM_CYFRAME) { regs[0] = 1; return true; }
        if (idx == 92 /* SM_CXPADDEDBORDER */) { regs[0] = 0; return true; }
        regs[0] = GetSystemMetrics(idx);
        LOG(API, "[API] GetSystemMetrics(%d) -> %d\n", idx, regs[0]);
        return true;
    });
    Thunk("GetSysColor", 889, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        /* WinCE passes color indices with 0x40000000 flag — strip it. */
        int idx = regs[0] & 0x3FFFFFFF;
        /* When theming is active, return WinCE colors directly (including
           WinCE-only indices 25=COLOR_STATIC, 26=COLOR_STATICTEXT). */
        if (enable_theming) {
            regs[0] = GetWceThemeColor(idx);
        } else {
            /* Without theming, map WinCE-only colors to desktop equivalents */
            if (idx == 25) idx = COLOR_3DFACE;
            else if (idx == 26) idx = COLOR_WINDOWTEXT;
            regs[0] = GetSysColor(idx);
        }
        return true;
    });
    Thunk("GetSysColorBrush", 937, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        int idx = regs[0] & 0x3FFFFFFF;
        if (enable_theming) {
            regs[0] = (uint32_t)(uintptr_t)GetWceThemeBrush(idx);
        } else {
            if (idx == 25) idx = COLOR_3DFACE;
            else if (idx == 26) idx = COLOR_WINDOWTEXT;
            regs[0] = (uint32_t)(uintptr_t)GetSysColorBrush(idx);
        }
        return true;
    });
    Thunk("GetTickCount", 535, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetTickCount(); return true;
    });
    Thunk("QueryPerformanceCounter", 538, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LARGE_INTEGER counter;
        BOOL result = QueryPerformanceCounter(&counter);
        if (regs[0]) {
            mem.Write32(regs[0], (uint32_t)(counter.QuadPart & 0xFFFFFFFF));
            mem.Write32(regs[0] + 4, (uint32_t)(counter.QuadPart >> 32));
        }
        regs[0] = result;
        return true;
    });
    Thunk("QueryPerformanceFrequency", 539, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LARGE_INTEGER freq;
        BOOL result = QueryPerformanceFrequency(&freq);
        if (regs[0]) {
            mem.Write32(regs[0], (uint32_t)(freq.QuadPart & 0xFFFFFFFF));
            mem.Write32(regs[0] + 4, (uint32_t)(freq.QuadPart >> 32));
        }
        regs[0] = result;
        return true;
    });
    Thunk("Sleep", 496, [](uint32_t* regs, EmulatedMemory&) -> bool {
        Sleep(regs[0]); return true;
    });
    Thunk("GetLocalTime", 23, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        SYSTEMTIME st; GetLocalTime(&st);
        if (regs[0]) {
            mem.Write16(regs[0]+0, st.wYear); mem.Write16(regs[0]+2, st.wMonth);
            mem.Write16(regs[0]+4, st.wDayOfWeek); mem.Write16(regs[0]+6, st.wDay);
            mem.Write16(regs[0]+8, st.wHour); mem.Write16(regs[0]+10, st.wMinute);
            mem.Write16(regs[0]+12, st.wSecond); mem.Write16(regs[0]+14, st.wMilliseconds);
        }
        return true;
    });
    Thunk("GetSystemTime", 25, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        SYSTEMTIME st; GetSystemTime(&st);
        if (regs[0]) {
            mem.Write16(regs[0]+0, st.wYear); mem.Write16(regs[0]+2, st.wMonth);
            mem.Write16(regs[0]+4, st.wDayOfWeek); mem.Write16(regs[0]+6, st.wDay);
            mem.Write16(regs[0]+8, st.wHour); mem.Write16(regs[0]+10, st.wMinute);
            mem.Write16(regs[0]+12, st.wSecond); mem.Write16(regs[0]+14, st.wMilliseconds);
        }
        return true;
    });
    Thunk("GetProcessVersion", 536, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x0400000A; return true;
    });
    Thunk("GetOwnerProcess", 606, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetCurrentProcessId(); return true;
    });
    Thunk("GetStartupInfoW", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        for (int i = 0; i < 68; i += 4) mem.Write32(regs[0] + i, 0);
        mem.Write32(regs[0], 68); return true;
    });
    Thunk("IsAPIReady", 30, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] IsAPIReady(%d) -> TRUE\n", regs[0]);
        regs[0] = 1; return true;
    });
    /* Ordinal-only entries */
    ThunkOrdinal("GetTimeZoneInformation", 27);
    Thunk("CompareFileTime", 18, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* CompareFileTime(lpFileTime1, lpFileTime2) -> -1, 0, or 1 */
        uint32_t a1 = regs[0], a2 = regs[1];
        FILETIME ft1 = { mem.Read32(a1), mem.Read32(a1 + 4) };
        FILETIME ft2 = { mem.Read32(a2), mem.Read32(a2 + 4) };
        regs[0] = (uint32_t)CompareFileTime(&ft1, &ft2);
        return true;
    });
    Thunk("SystemTimeToFileTime", 19, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t st_addr = regs[0], ft_addr = regs[1];
        SYSTEMTIME st = {};
        st.wYear = mem.Read16(st_addr);
        st.wMonth = mem.Read16(st_addr + 2);
        st.wDayOfWeek = mem.Read16(st_addr + 4);
        st.wDay = mem.Read16(st_addr + 6);
        st.wHour = mem.Read16(st_addr + 8);
        st.wMinute = mem.Read16(st_addr + 10);
        st.wSecond = mem.Read16(st_addr + 12);
        st.wMilliseconds = mem.Read16(st_addr + 14);
        FILETIME ft;
        BOOL ok = SystemTimeToFileTime(&st, &ft);
        if (ok && ft_addr) {
            mem.Write32(ft_addr, ft.dwLowDateTime);
            mem.Write32(ft_addr + 4, ft.dwHighDateTime);
        }
        LOG(API, "[API] SystemTimeToFileTime(%d/%d/%d %d:%d:%d) -> %s\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            ok ? "TRUE" : "FALSE");
        regs[0] = ok;
        return true;
    });
    ThunkOrdinal("SetLocalTime", 24);
    ThunkOrdinal("CreateThread", 492);
    ThunkOrdinal("TerminateThread", 491);
    ThunkOrdinal("GetExitCodeProcess", 519);
    ThunkOrdinal("SetThreadPriority", 514);
    ThunkOrdinal("OpenProcess", 509);
    ThunkOrdinal("CreateFileMappingW", 548);
    ThunkOrdinal("GetWindowThreadProcessId", 292);
    ThunkOrdinal("CreateProcessW", 493);
    ThunkOrdinal("WaitForAPIReady", 2562);
    ThunkOrdinal("FlushInstructionCache", 508);
    ThunkOrdinal("MapViewOfFile", 549);
    ThunkOrdinal("UnmapViewOfFile", 550);
}
