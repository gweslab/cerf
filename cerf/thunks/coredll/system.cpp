/* System thunks: GetSystemMetrics, time, sync, TLS, locale */
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
        /* WinCE uses 1px edges vs 2px on desktop Windows. ARM commctrl.dll
           toolbar code depends on this for correct button width calculation. */
        if (idx == SM_CXEDGE || idx == SM_CYEDGE) { regs[0] = 1; return true; }
        regs[0] = GetSystemMetrics(idx);
        LOG(API, "[API] GetSystemMetrics(%d) -> %d\n", idx, regs[0]);
        return true;
    });
    Thunk("GetSysColor", 889, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* WinCE passes color indices with 0x40000000 flag — strip it.
           WinCE added COLOR_STATIC=25 and COLOR_STATICTEXT=26 which don't
           exist on desktop Windows (index 25 is undefined, 26 is COLOR_HOTLIGHT).
           Map them to appropriate desktop equivalents. */
        int idx = regs[0] & 0x3FFFFFFF;
        if (idx == 25) idx = COLOR_3DFACE;     /* WinCE COLOR_STATIC */
        else if (idx == 26) idx = COLOR_WINDOWTEXT; /* WinCE COLOR_STATICTEXT */
        regs[0] = GetSysColor(idx); return true;
    });
    Thunk("GetSysColorBrush", 937, [](uint32_t* regs, EmulatedMemory&) -> bool {
        int idx = regs[0] & 0x3FFFFFFF;
        if (idx == 25) idx = COLOR_3DFACE;
        else if (idx == 26) idx = COLOR_WINDOWTEXT;
        regs[0] = (uint32_t)(uintptr_t)GetSysColorBrush(idx); return true;
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
    Thunk("GetSystemInfo", 542, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        if (regs[0]) {
            SYSTEM_INFO si; GetSystemInfo(&si);
            mem.Write32(regs[0]+0, 0); mem.Write32(regs[0]+4, si.dwPageSize);
            mem.Write32(regs[0]+8, 0x10000); mem.Write32(regs[0]+12, 0x7FFFFFFF);
            mem.Write32(regs[0]+20, 1); mem.Write32(regs[0]+24, 0x4);
        }
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
    /* Sync */
    Thunk("InitializeCriticalSection", 2, [](uint32_t*, EmulatedMemory&) -> bool { return true; });
    Thunk("DeleteCriticalSection", 3, [](uint32_t*, EmulatedMemory&) -> bool { return true; });
    Thunk("EnterCriticalSection", 4, [](uint32_t*, EmulatedMemory&) -> bool { return true; });
    Thunk("LeaveCriticalSection", 5, [](uint32_t*, EmulatedMemory&) -> bool { return true; });
    Thunk("InitLocale", 8, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    Thunk("InterlockedIncrement", 10, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int32_t val = (int32_t)mem.Read32(regs[0]) + 1;
        mem.Write32(regs[0], (uint32_t)val);
        regs[0] = (uint32_t)val;
        return true;
    });
    ThunkOrdinal("InterlockedDecrement", 11);
    Thunk("InterlockedDecrement", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int32_t val = (int32_t)mem.Read32(regs[0]) - 1;
        mem.Write32(regs[0], (uint32_t)val);
        regs[0] = (uint32_t)val;
        return true;
    });
    Thunk("InterlockedExchange", 12, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old = mem.Read32(regs[0]);
        mem.Write32(regs[0], regs[1]);
        regs[0] = old;
        return true;
    });
    Thunk("InterlockedCompareExchange", 1492, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* R0=Destination, R1=Exchange, R2=Comperand
           If *Destination == Comperand, store Exchange; return original value */
        uint32_t original = mem.Read32(regs[0]);
        if (original == regs[2]) {
            mem.Write32(regs[0], regs[1]);
        }
        LOG(API, "[API] InterlockedCompareExchange(0x%08X, exch=0x%08X, comp=0x%08X) -> 0x%08X %s\n",
            regs[0], regs[1], regs[2], original, (original == regs[2]) ? "(exchanged)" : "(no change)");
        regs[0] = original;
        return true;
    });
    Thunk("CreateEventW", 495, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreateEventW(NULL, regs[1], regs[2], NULL); return true;
    });
    Thunk("WaitForSingleObject", 497, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = WaitForSingleObject((HANDLE)(intptr_t)(int32_t)regs[0], regs[1]); return true;
    });
    Thunk("CloseHandle", 553, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t fake = regs[0]; HANDLE h = UnwrapHandle(fake);
        regs[0] = CloseHandle(h); RemoveHandle(fake); return true;
    });
    Thunk("CreateMutexW", 555, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreateMutexW(NULL, regs[1], NULL); return true;
    });
    Thunk("ReleaseMutex", 556, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ReleaseMutex((HANDLE)(intptr_t)(int32_t)regs[0]); return true;
    });
    /* TLS — emulated via the KData page at 0xFFFFC800.
       WinCE ARM code can access TLS directly through memory:
         lpvTls = *(DWORD*)0xFFFFC800   (pointer to TLS slot array)
         value  = lpvTls[slot_index]     (read slot)
       TLS slot array at 0xFFFFC01C, set up in Win32Thunks constructor.
       Slots 0-3 reserved by WinCE; TlsCall allocates from 4 onward.
       Next-free counter stored at 0xFFFFC880 (KData padding area). */
    Thunk("TlsGetValue", 15, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t idx = regs[0];
        if (idx < 64) {
            regs[0] = mem.Read32(0xFFFFC01C + idx * 4);
        } else {
            regs[0] = 0;
        }
        SetLastError(ERROR_SUCCESS);
        LOG(API, "[API] TlsGetValue(%u) -> 0x%08X\n", idx, regs[0]);
        return true;
    });
    Thunk("TlsSetValue", 16, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t idx = regs[0];
        if (idx < 64) {
            mem.Write32(0xFFFFC01C + idx * 4, regs[1]);
            LOG(API, "[API] TlsSetValue(%u, 0x%08X) -> 1\n", idx, regs[1]);
            regs[0] = 1;
        } else {
            LOG(API, "[API] TlsSetValue(%u) -> 0 (out of range)\n", idx);
            regs[0] = 0;
        }
        return true;
    });
    /* TlsCall: next-free counter stored at 0xFFFFC880 (KData padding area).
       Initialize to 4 (slots 0-3 are reserved by WinCE). */
    mem.Write32(0xFFFFC880, 4);
    Thunk("TlsCall", 520, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t next = mem.Read32(0xFFFFC880);
        if (next < 64) {
            mem.Write32(0xFFFFC880, next + 1);
            LOG(API, "[API] TlsCall() -> slot %u\n", next);
            regs[0] = next;
        } else {
            LOG(API, "[API] TlsCall() -> 0 (out of slots)\n");
            regs[0] = 0;
        }
        return true;
    });
    /* Locale */
    Thunk("GetLocaleInfoW", 200, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        wchar_t buf[256] = {}; uint32_t maxlen = regs[3]; if (maxlen > 256) maxlen = 256;
        int ret = GetLocaleInfoW(regs[0], regs[1], buf, (int)maxlen);
        for (int i = 0; i < ret; i++) mem.Write16(regs[2] + i * 2, buf[i]);
        regs[0] = ret; return true;
    });
    Thunk("GetSystemDefaultLangID", 211, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetSystemDefaultLangID(); return true;
    });
    Thunk("GetUserDefaultLangID", 212, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetUserDefaultLangID(); return true;
    });
    Thunk("GetUserDefaultLCID", 215, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetUserDefaultLCID(); return true;
    });
    Thunk("GetSystemDefaultLCID", 213, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetSystemDefaultLCID(); return true;
    });
    Thunk("ConvertDefaultLocale", 210, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ConvertDefaultLocale(regs[0]); return true;
    });
    Thunk("GetACP", 186, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetACP(); return true; });
    Thunk("GetOEMCP", 187, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetOEMCP(); return true; });
    Thunk("GetCPInfo", 188, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("LCMapStringW", [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    /* GetTimeFormatW(Locale, dwFlags, lpTime, lpFormat, lpTimeStr, cchTime)
       r0=Locale, r1=dwFlags, r2=lpTime(ARM ptr to SYSTEMTIME), r3=lpFormat(ARM ptr),
       stack[0]=lpTimeStr(ARM ptr), stack[1]=cchTime */
    Thunk("GetTimeFormatW", 202, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LCID locale = regs[0];
        DWORD flags = regs[1];
        uint32_t lpTime_addr = regs[2];
        uint32_t lpFormat_addr = regs[3];
        uint32_t lpOut_addr = ReadStackArg(regs, mem, 0);
        int cch = (int)ReadStackArg(regs, mem, 1);
        SYSTEMTIME st = {}, *pst = NULL;
        if (lpTime_addr) {
            st.wYear = mem.Read16(lpTime_addr);
            st.wMonth = mem.Read16(lpTime_addr + 2);
            st.wDayOfWeek = mem.Read16(lpTime_addr + 4);
            st.wDay = mem.Read16(lpTime_addr + 6);
            st.wHour = mem.Read16(lpTime_addr + 8);
            st.wMinute = mem.Read16(lpTime_addr + 10);
            st.wSecond = mem.Read16(lpTime_addr + 12);
            st.wMilliseconds = mem.Read16(lpTime_addr + 14);
            pst = &st;
        }
        std::wstring fmt;
        LPCWSTR pFmt = NULL;
        if (lpFormat_addr) { fmt = ReadWStringFromEmu(mem, lpFormat_addr); pFmt = fmt.c_str(); }
        wchar_t buf[256] = {};
        int ret = GetTimeFormatW(locale, flags, pst, pFmt, buf, 256);
        if (ret > 0 && lpOut_addr && cch > 0) {
            int copy = (ret < cch) ? ret : cch;
            for (int i = 0; i < copy; i++) mem.Write16(lpOut_addr + i * 2, buf[i]);
        } else if (cch == 0) {
            /* Query mode: return required size */
        }
        LOG(API, "[API] GetTimeFormatW(locale=0x%X, flags=0x%X, fmt=%ls) -> %d '%ls'\n",
            locale, flags, pFmt ? pFmt : L"(null)", ret, buf);
        regs[0] = ret;
        return true;
    });
    /* GetDateFormatW — same signature as GetTimeFormatW */
    Thunk("GetDateFormatW", 203, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LCID locale = regs[0];
        DWORD flags = regs[1];
        uint32_t lpDate_addr = regs[2];
        uint32_t lpFormat_addr = regs[3];
        uint32_t lpOut_addr = ReadStackArg(regs, mem, 0);
        int cch = (int)ReadStackArg(regs, mem, 1);
        SYSTEMTIME st = {}, *pst = NULL;
        if (lpDate_addr) {
            st.wYear = mem.Read16(lpDate_addr);
            st.wMonth = mem.Read16(lpDate_addr + 2);
            st.wDayOfWeek = mem.Read16(lpDate_addr + 4);
            st.wDay = mem.Read16(lpDate_addr + 6);
            st.wHour = mem.Read16(lpDate_addr + 8);
            st.wMinute = mem.Read16(lpDate_addr + 10);
            st.wSecond = mem.Read16(lpDate_addr + 12);
            st.wMilliseconds = mem.Read16(lpDate_addr + 14);
            pst = &st;
        }
        std::wstring fmt;
        LPCWSTR pFmt = NULL;
        if (lpFormat_addr) { fmt = ReadWStringFromEmu(mem, lpFormat_addr); pFmt = fmt.c_str(); }
        wchar_t buf[256] = {};
        int ret = GetDateFormatW(locale, flags, pst, pFmt, buf, 256);
        if (ret > 0 && lpOut_addr && cch > 0) {
            int copy = (ret < cch) ? ret : cch;
            for (int i = 0; i < copy; i++) mem.Write16(lpOut_addr + i * 2, buf[i]);
        }
        LOG(API, "[API] GetDateFormatW(locale=0x%X, flags=0x%X) -> %d '%ls'\n",
            locale, flags, ret, buf);
        regs[0] = ret;
        return true;
    });
    Thunk("GetNumberFormatW", 204, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("GetCurrencyFormatW", 205, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    /* Version/info */
    Thunk("GetVersionExW", 717, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        if (regs[0]) {
            mem.Write32(regs[0]+4, 4); mem.Write32(regs[0]+8, 21);
            mem.Write32(regs[0]+12, 0); mem.Write32(regs[0]+16, 0);
        }
        regs[0] = 1; return true;
    });
    ThunkOrdinal("SystemParametersInfoW", 5403); /* WinCE 7 aygshell uses this ordinal */
    Thunk("SystemParametersInfoW", 89, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        UINT uiAction = regs[0], uiParam = regs[1];
        uint32_t pvParam = regs[2];
        UINT fWinIni = regs[3];
        if (uiAction == SPI_GETWORKAREA && pvParam) {
            uint32_t w = fake_screen_resolution ? screen_width : (uint32_t)GetSystemMetrics(SM_CXSCREEN);
            uint32_t h = fake_screen_resolution ? screen_height : (uint32_t)GetSystemMetrics(SM_CYSCREEN);
            mem.Write32(pvParam + 0,  0);    /* left */
            mem.Write32(pvParam + 4,  0);    /* top */
            mem.Write32(pvParam + 8,  w);    /* right */
            mem.Write32(pvParam + 12, h);    /* bottom */
            LOG(API, "[API] SystemParametersInfoW(SPI_GETWORKAREA) -> {0,0,%d,%d}\n", w, h);
            regs[0] = 1;
        } else if (uiAction == 0xE1 /* WinCE 7 SPI_GETSIPINFO via aygshell */ && pvParam) {
            /* WinCE Soft Input Panel info. Fill SIPINFO struct:
               cbSize(4) fdwFlags(4) rcVisibleDesktop(16) rcSipRect(16)
               dwImDataSize(4) pvImData(4) = 48 bytes.
               Report SIP as hidden, visible desktop = full work area. */
            mem.Write32(pvParam + 0,  48);    /* cbSize */
            mem.Write32(pvParam + 4,  0x2);   /* fdwFlags = SIPF_DOCKED (not SIPF_ON) */
            /* rcVisibleDesktop */
            uint32_t sw = fake_screen_resolution ? screen_width : (uint32_t)GetSystemMetrics(SM_CXSCREEN);
            uint32_t sh = fake_screen_resolution ? screen_height : (uint32_t)GetSystemMetrics(SM_CYSCREEN);
            mem.Write32(pvParam + 8,  0);     /* left */
            mem.Write32(pvParam + 12, 0);     /* top */
            mem.Write32(pvParam + 16, sw);    /* right */
            mem.Write32(pvParam + 20, sh);    /* bottom */
            /* rcSipRect = empty (SIP hidden) */
            mem.Write32(pvParam + 24, 0);
            mem.Write32(pvParam + 28, 0);
            mem.Write32(pvParam + 32, 0);
            mem.Write32(pvParam + 36, 0);
            mem.Write32(pvParam + 40, 0);  /* dwImDataSize */
            mem.Write32(pvParam + 44, 0);  /* pvImData */
            LOG(API, "[API] SystemParametersInfoW(0x%X/SPI_GETSIPINFO) -> vis={0,0,%d,%d}\n",
                uiAction, screen_width, screen_height);
            regs[0] = 1;
        } else if (uiAction == SPI_SETDESKWALLPAPER) {
            /* WinCE apps set wallpaper via SPI and expect WM_SETTINGCHANGE broadcast.
               The wallpaper path is a WinCE VFS path in ARM memory — don't forward to native. */
            std::wstring wp_path;
            if (pvParam) wp_path = ReadWStringFromEmu(mem, pvParam);
            LOG(API, "[API] SystemParametersInfoW(SPI_SETDESKWALLPAPER, '%ls')\n", wp_path.c_str());
            /* Broadcast WM_SETTINGCHANGE so the desktop reloads the wallpaper from registry */
            if (fWinIni & SPIF_SENDCHANGE)
                SendMessageW(HWND_BROADCAST, WM_SETTINGCHANGE, SPI_SETDESKWALLPAPER, 0);
            regs[0] = 1;
        } else {
            regs[0] = SystemParametersInfoW(uiAction, uiParam, NULL, fWinIni);
        }
        return true;
    });
    Thunk("GlobalMemoryStatus", 88, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t ptr = regs[0];
        if (ptr) {
            MEMORYSTATUS ms = {}; ms.dwLength = sizeof(ms); GlobalMemoryStatus(&ms);
            mem.Write32(ptr+0, 32); mem.Write32(ptr+4, ms.dwMemoryLoad);
            mem.Write32(ptr+8, (uint32_t)std::min(ms.dwTotalPhys, (SIZE_T)UINT32_MAX));
            mem.Write32(ptr+12, (uint32_t)std::min(ms.dwAvailPhys, (SIZE_T)UINT32_MAX));
            mem.Write32(ptr+16, (uint32_t)std::min(ms.dwTotalPageFile, (SIZE_T)UINT32_MAX));
            mem.Write32(ptr+20, (uint32_t)std::min(ms.dwAvailPageFile, (SIZE_T)UINT32_MAX));
            mem.Write32(ptr+24, (uint32_t)std::min(ms.dwTotalVirtual, (SIZE_T)UINT32_MAX));
            mem.Write32(ptr+28, (uint32_t)std::min(ms.dwAvailVirtual, (SIZE_T)UINT32_MAX));
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
    ThunkOrdinal("CompareFileTime", 18);
    ThunkOrdinal("SystemTimeToFileTime", 19);
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
