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
            LOG(API, "[API] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    auto stub1 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(API, "[API] [STUB] %s -> 1\n", name); regs[0] = 1; return true;
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
        LOG(API, "[API] RegisterDbgZones(hMod=0x%08X, lpdbgZones=0x%08X) -> TRUE (stub)\n", regs[0], regs[1]);
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
    /* Caret — real implementations needed by RichEdit for the blinking cursor */
    Thunk("CreateCaret", 658, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        HBITMAP hbm = (HBITMAP)(uintptr_t)regs[1];
        regs[0] = CreateCaret(hw, hbm, (int)regs[2], (int)regs[3]);
        return true;
    });
    Thunk("HideCaret", 660, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = HideCaret((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    });
    Thunk("ShowCaret", 661, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ShowCaret((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    });
    Thunk("GetCaretBlinkTime", 664, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetCaretBlinkTime();
        return true;
    });
    /* Sound */
    Thunk("sndPlaySoundW", 377, stub1("sndPlaySoundW"));
    Thunk("PlaySoundW", 378, stub1("PlaySoundW"));
    Thunk("waveOutSetVolume", 382, stub0("waveOutSetVolume"));
    /* RAS */
    Thunk("RasDial", 342, stub0("RasDial"));
    Thunk("RasHangup", stub0("RasHangup"));
    thunk_handlers["RasHangUp"] = thunk_handlers["RasHangup"];
    /* C runtime misc */
    Thunk("_purecall", 1092, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] _purecall\n"); regs[0] = 0; return true;
    });
    Thunk("terminate", 1556, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] terminate\n"); ExitProcess(3); return true;
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
    /* setjmp/longjmp + RaiseException integration:
       Track setjmp buffers so RaiseException(NONCONTINUABLE) can longjmp to recovery point.
       MFC uses setjmp/longjmp for C++ exception handling on WinCE. */
    /* setjmp: save callee-saved registers (r4-r11), SP, LR into jmp_buf at r0.
       ARM WinCE jmp_buf layout: r4, r5, r6, r7, r8, r9, r10, r11, r13(SP), r14(LR) = 10 words */
    Thunk("setjmp", 2054, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf = regs[0];
        if (buf) {
            for (int i = 4; i <= 11; i++) mem.Write32(buf + (i - 4) * 4, regs[i]);
            mem.Write32(buf + 8 * 4, regs[13]); /* SP */
            mem.Write32(buf + 9 * 4, regs[14]); /* LR (return address) */
            setjmp_stack.push_back(buf);
        }
        LOG(API, "[API] setjmp(buf=0x%08X, LR=0x%08X) -> 0 (stack depth=%zu)\n",
            buf, regs[14], setjmp_stack.size());
        regs[0] = 0;
        return true;
    });
    Thunk("_setjmp3", thunk_handlers["setjmp"]);
    /* longjmp: restore registers from jmp_buf, return val (or 1 if val==0) */
    Thunk("longjmp", 1036, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf = regs[0];
        uint32_t val = regs[1];
        if (val == 0) val = 1;
        if (buf) {
            for (int i = 4; i <= 11; i++) regs[i] = mem.Read32(buf + (i - 4) * 4);
            regs[13] = mem.Read32(buf + 8 * 4); /* SP */
            regs[14] = mem.Read32(buf + 9 * 4); /* LR */
            /* Pop setjmp stack back to this buffer (or further) */
            while (!setjmp_stack.empty() && setjmp_stack.back() != buf)
                setjmp_stack.pop_back();
            if (!setjmp_stack.empty()) setjmp_stack.pop_back();
        }
        LOG(API, "[API] longjmp(buf=0x%08X, val=%u) -> LR=0x%08X (stack depth=%zu)\n",
            buf, val, regs[14], setjmp_stack.size());
        regs[0] = val;
        return true;
    });
    /* Misc kernel stubs */
    Thunk("FlushInstructionCache", 508, stub1("FlushInstructionCache"));
    Thunk("GetProcessIndexFromID", stub1("GetProcessIndexFromID"));
    Thunk("EventModify", 494, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* WinCE EventModify(HANDLE hEvent, DWORD func)
           func: 1=EVENT_PULSE, 2=EVENT_RESET, 3=EVENT_SET */
        HANDLE hEvent = (HANDLE)(intptr_t)(int32_t)regs[0];
        uint32_t func = regs[1];
        BOOL result = FALSE;
        switch (func) {
            case 3: result = SetEvent(hEvent); break;    /* EVENT_SET */
            case 2: result = ResetEvent(hEvent); break;  /* EVENT_RESET */
            case 1: result = PulseEvent(hEvent); break;  /* EVENT_PULSE */
            default:
                LOG(API, "[API] EventModify(0x%p, func=%d) -> unknown func\n", hEvent, func);
                break;
        }
        LOG(API, "[API] EventModify(0x%p, func=%d) -> %d\n", hEvent, func, result);
        regs[0] = result;
        return true;
    });
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
        LOG(API, "[API] CoInitializeEx(0x%X) -> 0x%08X\n", regs[1], (uint32_t)hr);
        regs[0] = (uint32_t)hr;
        return true;
    });
    Thunk("CoUninitialize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] CoUninitialize()\n");
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
        LOG(API, "[API] RegisterClipboardFormatW('%ls')\n", fmt.c_str());
        UINT id = RegisterClipboardFormatW(fmt.c_str());
        regs[0] = id;
        return true;
    });
    Thunk("GetClipboardOwner", 670, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] GetClipboardOwner() -> NULL (stub)\n");
        regs[0] = 0;
        return true;
    });
    /* Monitor */
    Thunk("MonitorFromWindow", 1524, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] MonitorFromWindow(hwnd=0x%08X, flags=0x%X) -> stub\n", regs[0], regs[1]);
        regs[0] = 1; /* fake monitor handle */
        return true;
    });
    Thunk("GetMonitorInfo", 1525, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] GetMonitorInfo(hMonitor=0x%08X, lpmi=0x%08X) -> stub\n", regs[0], regs[1]);
        if (regs[1]) {
            /* Fill MONITORINFO with emulated screen resolution */
            uint32_t addr = regs[1];
            /* cbSize already set by caller; rcMonitor */
            mem.Write32(addr + 4, 0); mem.Write32(addr + 8, 0);
            mem.Write32(addr + 12, screen_width); mem.Write32(addr + 16, screen_height);
            /* rcWork */
            mem.Write32(addr + 20, 0); mem.Write32(addr + 24, 0);
            mem.Write32(addr + 28, screen_width); mem.Write32(addr + 32, screen_height);
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
        LOG(API, "[API] ImmGetCompositionStringW(himc=0x%08X, dwIndex=0x%X) -> 0 (stub)\n", regs[0], regs[1]);
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
    /* Language */
    Thunk("GetUserDefaultUILanguage", 1318, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x0409; /* US English */
        return true;
    });
    Thunk("MonitorFromPoint", 1522, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 1; /* fake monitor handle */
        return true;
    });
    /* WinCE kernel stubs for explorer.exe */
    Thunk("RegisterTaskBar", 892, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] RegisterTaskBar(hwnd=0x%08X) -> 1\n", regs[0]);
        regs[0] = 1; return true;
    });
    Thunk("RegisterDesktop", 1507, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] RegisterDesktop(hwnd=0x%08X) -> 1\n", regs[0]);
        regs[0] = 1; return true;
    });
    ThunkOrdinal("RegisterTaskBarEx", 1506);
    thunk_handlers["RegisterTaskBarEx"] = thunk_handlers["RegisterTaskBar"];
    Thunk("SignalStarted", 639, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] SignalStarted(0x%08X) -> stub\n", regs[0]);
        regs[0] = 0; return true;
    });
    Thunk("OpenEventW", 1496, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* OpenEventW(dwDesiredAccess, bInheritHandle, lpName) — name is in R2 but
           WinCE often passes NULL name (unnamed events). Return NULL to indicate
           event doesn't exist yet (caller will CreateEventW). */
        LOG(API, "[API] OpenEventW(access=0x%X, inherit=%d) -> 0 (stub)\n", regs[0], regs[1]);
        regs[0] = 0; return true;
    });
    Thunk("CreateAPISet", 559, stub0("CreateAPISet"));
    Thunk("RegisterAPISet", 635, stub0("RegisterAPISet"));
    Thunk("SetProcPermissions", 611, stub1("SetProcPermissions"));
    Thunk("GetCurrentPermissions", 612, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0xFFFFFFFF; /* all permissions */
        return true;
    });
    Thunk("CompactAllHeaps", 54, stub0("CompactAllHeaps"));
    Thunk("MapCallerPtr", 1602, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* MapCallerPtr just returns the pointer unchanged in our single-process model */
        LOG(API, "[API] MapCallerPtr(ptr=0x%08X, size=%u) -> 0x%08X\n", regs[0], regs[1], regs[0]);
        return true; /* regs[0] already contains the pointer */
    });
    Thunk("GetExitCodeThread", 518, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] GetExitCodeThread -> 0\n");
        regs[0] = 0; return true;
    });
    Thunk("GetThreadPriority", 515, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; /* THREAD_PRIORITY_NORMAL */
        return true;
    });
    Thunk("SendMessageTimeout", 1495, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        regs[0] = (uint32_t)SendMessageW(hw, regs[1], regs[2], regs[3]);
        return true;
    });
    Thunk("GetWindowTextWDirect", 1454, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        int maxlen = (int)regs[2];
        wchar_t buf[256] = {};
        if (maxlen > 256) maxlen = 256;
        int len = GetWindowTextW(hw, buf, maxlen);
        uint32_t dst = regs[1];
        for (int i = 0; i <= len; i++) mem.Write16(dst + i * 2, buf[i]);
        regs[0] = len;
        return true;
    });
    /* WinCE kernel stubs for power/notification */
    Thunk("CreateMsgQueue", 1529, stub0("CreateMsgQueue"));
    Thunk("ReadMsgQueue", 1530, stub0("ReadMsgQueue"));
    Thunk("RequestPowerNotifications", 1585, stub0("RequestPowerNotifications"));
    Thunk("StopPowerNotifications", 1586, stub0("StopPowerNotifications"));
    Thunk("FindFirstChangeNotificationW", 1682, stub0("FindFirstChangeNotificationW"));
    Thunk("FindCloseChangeNotification", 1684, stub0("FindCloseChangeNotification"));
    Thunk("CeRunAppAtEvent", 476, stub0("CeRunAppAtEvent"));
    Thunk("CeOidGetInfo", 312, stub0("CeOidGetInfo"));
    Thunk("GwesPowerOffSystem", 296, stub0("GwesPowerOffSystem"));
    Thunk("RectangleAnimation", 294, stub0("RectangleAnimation"));
    Thunk("TouchCalibrate", 877, stub0("TouchCalibrate"));
    Thunk("TerminateProcess", 544, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] TerminateProcess(hProcess=0x%08X, exitCode=%d)\n", regs[0], regs[1]);
        regs[0] = 1; return true;
    });
    Thunk("GetKeyboardLayoutList", 1767, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        if (regs[0] > 0 && regs[1]) {
            mem.Write32(regs[1], 0x04090409); /* US English */
            regs[0] = 1;
        } else {
            regs[0] = 1; /* number of layouts */
        }
        return true;
    });
    Thunk("SHLoadIndirectString", 1977, stub0("SHLoadIndirectString"));
    Thunk("CeOpenDatabaseEx2", 1469, stub0("CeOpenDatabaseEx2"));
    Thunk("IsBadCodePtr", 521, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; /* Always return FALSE - pointer is valid */
        return true;
    });
    Thunk("GetKeyState", 860, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)GetKeyState((int)regs[0]); return true;
    });
    Thunk("SetSysColors", 890, stub0("SetSysColors"));
    Thunk("GetAsyncKeyState", 826, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)GetAsyncKeyState((int)regs[0]); return true;
    });
    /* Ordinal-only entries */
    ThunkOrdinal("GetOwnerProcess", 606);
    ThunkOrdinal("Random", 80);
    /* COM — WinCE coredll re-exports some COM functions */
    Thunk("CoInitialize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] CoInitialize(pvReserved=0x%08X) -> S_OK\n", regs[0]);
        HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        regs[0] = (uint32_t)hr;
        return true;
    });
    Thunk("OleInitialize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] OleInitialize(pvReserved=0x%08X) -> S_OK (stub)\n", regs[0]);
        regs[0] = 0; /* S_OK */
        return true;
    });
    Thunk("OleUninitialize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] OleUninitialize() -> stub\n");
        return true;
    });
    Thunk("CoCreateInstance", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] CoCreateInstance(rclsid=0x%08X, ...) -> E_NOTIMPL (stub)\n", regs[0]);
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });
    Thunk("CoTaskMemAlloc", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size = regs[0];
        LOG(API, "[API] CoTaskMemAlloc(cb=%u)\n", size);
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
        LOG(API, "[API] CoTaskMemFree(pv=0x%08X) -> stub\n", regs[0]);
        return true;
    });
    Thunk("StringFromGUID2", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t guid_addr = regs[0], buf_addr = regs[1], cchMax = regs[2];
        LOG(API, "[API] StringFromGUID2(rguid=0x%08X, lpsz=0x%08X, cchMax=%d)\n",
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
        LOG(API, "[API] CoCreateGuid(pguid=0x%08X)\n", regs[0]);
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
