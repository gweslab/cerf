#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Misc small stubs: debug, clipboard, caret, sound, RAS, COM, IMM, gestures,
   C runtime */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <objbase.h>
void Win32Thunks::RegisterMiscHandlers() {
    auto stub0 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(THUNK, "[THUNK] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    auto stub1 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(THUNK, "[THUNK] [STUB] %s -> 1\n", name); regs[0] = 1; return true;
        };
    };
    /* SIP (Software Input Panel) */
    Thunk("SipGetInfo", stub0("SipGetInfo"));
    /* Debug */
    Thunk("OutputDebugStringW", 541, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(DBG, "[DEBUG] %ls\n", ReadWStringFromEmu(mem, regs[0]).c_str()); return true;
    });
    Thunk("NKDbgPrintfW", 545, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring fmt = ReadWStringFromEmu(mem, regs[0]);
        /* Simple substitution for common format specifiers using R1-R3 */
        std::wstring out;
        uint32_t argRegs[] = { regs[1], regs[2], regs[3] };
        int argIdx = 0;
        for (size_t i = 0; i < fmt.size(); i++) {
            if (fmt[i] == L'%' && i + 1 < fmt.size()) {
                wchar_t spec = fmt[i + 1];
                if (spec == L's' && argIdx < 3) {
                    out += ReadWStringFromEmu(mem, argRegs[argIdx++]);
                    i++; continue;
                } else if (spec == L'S' && argIdx < 3) {
                    /* %S = narrow string in wide printf */
                    std::string narrow;
                    uint32_t addr = argRegs[argIdx++];
                    for (uint32_t c; addr && (c = mem.Read8(addr)); addr++) narrow += (char)c;
                    out += std::wstring(narrow.begin(), narrow.end());
                    i++; continue;
                } else if ((spec == L'd' || spec == L'u') && argIdx < 3) {
                    out += std::to_wstring(argRegs[argIdx++]);
                    i++; continue;
                } else if (spec == L'x' && argIdx < 3) {
                    wchar_t hex[16]; swprintf(hex, 16, L"%x", argRegs[argIdx++]);
                    out += hex; i++; continue;
                } else if (spec == L'X' && argIdx < 3) {
                    wchar_t hex[16]; swprintf(hex, 16, L"%X", argRegs[argIdx++]);
                    out += hex; i++; continue;
                }
            }
            out += fmt[i];
        }
        LOG(DBG, "[NKDbg] %ls\n", out.c_str());
        return true;
    });
    Thunk("RegisterDbgZones", 546, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] RegisterDbgZones(hMod=0x%08X, lpdbgZones=0x%08X) -> TRUE (stub)\n", regs[0], regs[1]);
        regs[0] = 1; return true;
    });
    /* Clipboard */
    Thunk("OpenClipboard", 668, stub1("OpenClipboard"));
    Thunk("CloseClipboard", 669, stub1("CloseClipboard"));
    Thunk("EmptyClipboard", 677, stub1("EmptyClipboard"));
    Thunk("GetClipboardData", 672, stub0("GetClipboardData"));
    Thunk("SetClipboardData", 671, stub0("SetClipboardData"));
    Thunk("IsClipboardFormatAvailable", 678, stub0("IsClipboardFormatAvailable"));
    Thunk("EnumClipboardFormats", 675, stub0("EnumClipboardFormats"));
    /* Caret */
    Thunk("CreateCaret", 658, stub1("CreateCaret"));
    Thunk("HideCaret", 660, stub1("HideCaret"));
    Thunk("ShowCaret", 661, stub1("ShowCaret"));
    /* Sound */
    Thunk("sndPlaySoundW", 377, stub1("sndPlaySoundW"));
    Thunk("waveOutSetVolume", 382, stub0("waveOutSetVolume"));
    /* RAS */
    Thunk("RasDial", 342, stub0("RasDial"));
    Thunk("RasHangup", stub0("RasHangup"));
    thunk_handlers["RasHangUp"] = thunk_handlers["RasHangup"];
    /* C runtime misc */
    Thunk("_purecall", 1092, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] _purecall\n"); regs[0] = 0; return true;
    });
    Thunk("terminate", 1556, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] terminate\n"); ExitProcess(3); return true;
    });
    Thunk("__security_gen_cookie", 1875, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0xBB40E64E; return true; });
    Thunk("__security_gen_cookie2", 2696, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0xBB40E64E; return true; });
    Thunk("CeGenRandom", 1601, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        for (uint32_t i = 0; i < regs[0]; i++) mem.Write8(regs[1] + i, (uint8_t)(rand() & 0xFF));
        regs[0] = 1; return true;
    });
    Thunk("MulDiv", 1877, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = MulDiv((int)regs[0], (int)regs[1], (int)regs[2]); return true;
    });
    Thunk("_except_handler4_common", 87, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("setjmp", 2054, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("_setjmp3", [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    /* Misc kernel stubs */
    Thunk("FlushInstructionCache", 508, stub1("FlushInstructionCache"));
    Thunk("GetProcessIndexFromID", stub1("GetProcessIndexFromID"));
    Thunk("EventModify", 494, stub1("EventModify"));
    Thunk("GlobalAddAtomW", 1519, stub1("GlobalAddAtomW"));
    Thunk("GetAPIAddress", 32, stub0("GetAPIAddress"));
    Thunk("WaitForAPIReady", 2562, stub0("WaitForAPIReady"));
    Thunk("__GetUserKData", 2528, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Return the standard PUserKData address (0xFFFFC800).
           The KData page is set up in the Win32Thunks constructor with:
             offset 0x000: lpvTls (pointer to emulated TLS slot array)
             offset 0x004: SH_CURTHREAD (current thread ID)
             offset 0x008: SH_CURPROC (current process ID) */
        regs[0] = 0xFFFFC800;
        return true;
    });
    /* Gesture stubs */
    Thunk("RegisterDefaultGestureHandler", 2928, stub0("RegisterDefaultGestureHandler"));
    Thunk("GetGestureInfo", 2925, stub0("GetGestureInfo"));
    Thunk("GetGestureExtraArguments", stub0("GetGestureExtraArguments"));
    Thunk("CloseGestureInfoHandle", 2924, stub0("CloseGestureInfoHandle"));
    /* COM — WinCE coredll re-exports COM functions from ole32. Both DLLs resolve
       to the same handler here since our dispatch is name-based (flat map). */
    Thunk("CoInitializeEx", [](uint32_t* regs, EmulatedMemory&) -> bool {
        HRESULT hr = CoInitializeEx(NULL, regs[1]);
        LOG(THUNK, "[THUNK] CoInitializeEx(0x%X) -> 0x%08X\n", regs[1], (uint32_t)hr);
        regs[0] = (uint32_t)hr;
        return true;
    });
    Thunk("CoUninitialize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] CoUninitialize()\n");
        CoUninitialize(); regs[0] = 0; return true;
    });
    /* IMM stubs */
    Thunk("ImmAssociateContext", 770, stub0("ImmAssociateContext"));
    Thunk("ImmGetContext", 783, stub0("ImmGetContext"));
    Thunk("ImmReleaseContext", 803, stub0("ImmReleaseContext"));
    Thunk("ImmGetOpenStatus", 792, stub0("ImmGetOpenStatus"));
    Thunk("ImmNotifyIME", 800, stub0("ImmNotifyIME"));
    Thunk("ImmSetOpenStatus", 814, stub0("ImmSetOpenStatus"));
    /* Clipboard */
    Thunk("RegisterClipboardFormatW", 673, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring fmt = ReadWStringFromEmu(mem, regs[0]);
        LOG(THUNK, "[THUNK] RegisterClipboardFormatW('%ls')\n", fmt.c_str());
        UINT id = RegisterClipboardFormatW(fmt.c_str());
        regs[0] = id;
        return true;
    });
    Thunk("GetClipboardOwner", 670, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] GetClipboardOwner() -> NULL (stub)\n");
        regs[0] = 0;
        return true;
    });
    /* Monitor */
    Thunk("MonitorFromWindow", 1524, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] MonitorFromWindow(hwnd=0x%08X, flags=0x%X) -> stub\n", regs[0], regs[1]);
        regs[0] = 1; /* fake monitor handle */
        return true;
    });
    Thunk("GetMonitorInfo", 1525, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(THUNK, "[THUNK] GetMonitorInfo(hMonitor=0x%08X, lpmi=0x%08X) -> stub\n", regs[0], regs[1]);
        if (regs[1]) {
            /* Fill MONITORINFO with desktop work area */
            RECT wa;
            SystemParametersInfo(SPI_GETWORKAREA, 0, &wa, 0);
            uint32_t addr = regs[1];
            /* cbSize already set by caller; rcMonitor */
            mem.Write32(addr + 4, 0); mem.Write32(addr + 8, 0);
            mem.Write32(addr + 12, wa.right); mem.Write32(addr + 16, wa.bottom);
            /* rcWork */
            mem.Write32(addr + 20, wa.left); mem.Write32(addr + 24, wa.top);
            mem.Write32(addr + 28, wa.right); mem.Write32(addr + 32, wa.bottom);
            /* dwFlags = MONITORINFOF_PRIMARY */
            mem.Write32(addr + 36, 1);
        }
        regs[0] = 1;
        return true;
    });
    /* Additional IMM stubs needed by RICHED20.DLL */
    Thunk("ImmEscapeW", 775, stub0("ImmEscapeW"));
    Thunk("ImmGetCandidateWindow", 779, stub0("ImmGetCandidateWindow"));
    Thunk("ImmGetCompositionStringW", 781, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] ImmGetCompositionStringW(himc=0x%08X, dwIndex=0x%X) -> 0 (stub)\n", regs[0], regs[1]);
        regs[0] = 0; return true;
    });
    Thunk("ImmGetConversionStatus", 785, stub0("ImmGetConversionStatus"));
    Thunk("ImmGetProperty", 793, stub0("ImmGetProperty"));
    Thunk("ImmSetCandidateWindow", 807, stub0("ImmSetCandidateWindow"));
    Thunk("ImmSetCompositionFontW", 808, stub0("ImmSetCompositionFontW"));
    Thunk("ImmSetCompositionStringW", 809, stub0("ImmSetCompositionStringW"));
    Thunk("ImmSetCompositionWindow", 810, stub0("ImmSetCompositionWindow"));
    Thunk("ImmGetVirtualKey", 1210, stub0("ImmGetVirtualKey"));
    Thunk("PostKeybdMessage", 832, stub0("PostKeybdMessage"));
    /* Memory validation */
    Thunk("IsBadReadPtr", 522, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; /* Always return FALSE - pointer is valid */
        return true;
    });
    Thunk("IsBadWritePtr", 523, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; return true;
    });
    /* Keyboard */
    Thunk("GetKeyboardLayout", 1229, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x04090409; /* US English */
        return true;
    });
    /* Ordinal-only entries */
    ThunkOrdinal("GetOwnerProcess", 606);
    ThunkOrdinal("Random", 80);
    /* COM — WinCE coredll re-exports some COM functions */
    Thunk("CoInitialize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] CoInitialize(pvReserved=0x%08X) -> S_OK\n", regs[0]);
        HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        regs[0] = (uint32_t)hr;
        return true;
    });
    Thunk("OleInitialize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] OleInitialize(pvReserved=0x%08X) -> S_OK (stub)\n", regs[0]);
        regs[0] = 0; /* S_OK */
        return true;
    });
    Thunk("OleUninitialize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] OleUninitialize() -> stub\n");
        return true;
    });
    Thunk("CoCreateInstance", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] CoCreateInstance(rclsid=0x%08X, ...) -> E_NOTIMPL (stub)\n", regs[0]);
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });
    Thunk("CoTaskMemAlloc", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size = regs[0];
        LOG(THUNK, "[THUNK] CoTaskMemAlloc(cb=%u)\n", size);
        uint32_t ptr = 0;
        if (size > 0) {
            static uint32_t cotask_heap = 0x60000000;
            ptr = cotask_heap;
            cotask_heap += (size + 0xFFF) & ~0xFFF;
            mem.Alloc(ptr, (size + 0xFFF) & ~0xFFF);
        }
        regs[0] = ptr;
        return true;
    });
    Thunk("CoTaskMemFree", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] CoTaskMemFree(pv=0x%08X) -> stub\n", regs[0]);
        return true;
    });
    Thunk("StringFromGUID2", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t guid_addr = regs[0], buf_addr = regs[1], cchMax = regs[2];
        LOG(THUNK, "[THUNK] StringFromGUID2(rguid=0x%08X, lpsz=0x%08X, cchMax=%d)\n",
               guid_addr, buf_addr, cchMax);
        if (guid_addr && buf_addr && cchMax >= 39) {
            uint32_t d1 = mem.Read32(guid_addr);
            uint16_t d2 = mem.Read16(guid_addr + 4);
            uint16_t d3 = mem.Read16(guid_addr + 6);
            wchar_t buf[40];
            swprintf(buf, 40, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                     d1, d2, d3,
                     mem.Read8(guid_addr + 8), mem.Read8(guid_addr + 9),
                     mem.Read8(guid_addr + 10), mem.Read8(guid_addr + 11),
                     mem.Read8(guid_addr + 12), mem.Read8(guid_addr + 13),
                     mem.Read8(guid_addr + 14), mem.Read8(guid_addr + 15));
            for (int i = 0; buf[i] && i < (int)cchMax; i++)
                mem.Write16(buf_addr + i * 2, buf[i]);
            mem.Write16(buf_addr + 38 * 2, 0);
            regs[0] = 39;
        } else {
            regs[0] = 0;
        }
        return true;
    });
    Thunk("CoCreateGuid", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(THUNK, "[THUNK] CoCreateGuid(pguid=0x%08X)\n", regs[0]);
        if (regs[0]) {
            for (int i = 0; i < 16; i++)
                mem.Write8(regs[0] + i, (uint8_t)(rand() & 0xFF));
        }
        regs[0] = 0; /* S_OK */
        return true;
    });
    Thunk("CoFileTimeNow", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        if (regs[0]) {
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            mem.Write32(regs[0], ft.dwLowDateTime);
            mem.Write32(regs[0] + 4, ft.dwHighDateTime);
        }
        regs[0] = 0;
        return true;
    });
    Thunk("CoFreeUnusedLibraries", [](uint32_t* regs, EmulatedMemory&) -> bool {
        return true;
    });
    Thunk("ReleaseStgMedium", [](uint32_t* regs, EmulatedMemory&) -> bool {
        return true;
    });
}
