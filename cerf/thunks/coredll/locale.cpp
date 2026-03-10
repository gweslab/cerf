/* Locale thunks: locale info, code pages, date/time/number/currency formatting */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"

void Win32Thunks::RegisterLocaleHandlers() {
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
}
