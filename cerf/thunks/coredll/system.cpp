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
    Thunk("RaiseException", 543, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] RaiseException(0x%08X) - ignoring\n", regs[0]); return true;
    });
    Thunk("GetSystemMetrics", 885, [](uint32_t* regs, EmulatedMemory&) -> bool {
        int idx = (int)regs[0];
        if (idx == SM_CXSCREEN || idx == SM_CYSCREEN) {
            RECT wa; SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
            regs[0] = (idx == SM_CXSCREEN)
                ? (uint32_t)(wa.right - wa.left) : (uint32_t)(wa.bottom - wa.top);
            return true;
        }
        regs[0] = GetSystemMetrics(idx); return true;
    });
    Thunk("GetSysColor", 889, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetSysColor(regs[0]); return true;
    });
    Thunk("GetSysColorBrush", 937, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetSysColorBrush(regs[0]); return true;
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
        LOG(THUNK, "[THUNK] TlsGetValue(%u) -> 0x%08X\n", idx, regs[0]);
        return true;
    });
    Thunk("TlsSetValue", 16, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t idx = regs[0];
        if (idx < 64) {
            mem.Write32(0xFFFFC01C + idx * 4, regs[1]);
            LOG(THUNK, "[THUNK] TlsSetValue(%u, 0x%08X) -> 1\n", idx, regs[1]);
            regs[0] = 1;
        } else {
            LOG(THUNK, "[THUNK] TlsSetValue(%u) -> 0 (out of range)\n", idx);
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
            LOG(THUNK, "[THUNK] TlsCall() -> slot %u\n", next);
            regs[0] = next;
        } else {
            LOG(THUNK, "[THUNK] TlsCall() -> 0 (out of slots)\n");
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
    Thunk("GetTimeFormatW", 202, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("GetDateFormatW", 203, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    /* Version/info */
    Thunk("GetVersionExW", 717, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        if (regs[0]) {
            mem.Write32(regs[0]+4, 4); mem.Write32(regs[0]+8, 21);
            mem.Write32(regs[0]+12, 0); mem.Write32(regs[0]+16, 0);
        }
        regs[0] = 1; return true;
    });
    Thunk("SystemParametersInfoW", 89, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SystemParametersInfoW(regs[0], regs[1], NULL, regs[3]); return true;
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
    /* Ordinal-only entries */
    ThunkOrdinal("GetTimeZoneInformation", 27);
    ThunkOrdinal("CompareFileTime", 18);
    ThunkOrdinal("SystemTimeToFileTime", 19);
    ThunkOrdinal("FileTimeToSystemTime", 20);
    ThunkOrdinal("FileTimeToLocalFileTime", 21);
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
