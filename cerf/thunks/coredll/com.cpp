#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* COM/OLE thunks: CoInitializeEx, CoUninitialize, CoCreateInstance, etc.
   WinCE coredll re-exports COM functions from ole32. We forward these
   to the real ARM ole32.dll so its internal state (TLS, apartments) is correct. */
#include "../win32_thunks.h"
#include "../../log.h"
#include "../../loader/pe_loader.h"
#include <cstdio>
#include <objbase.h>
void Win32Thunks::RegisterComHandlers() {
    /* Helper: resolve an export from the loaded ARM ole32.dll and cache it */
    auto resolveOle32 = [this](EmulatedMemory& mem, const char* func_name) -> uint32_t {
        static std::map<std::string, uint32_t> cache;
        auto it = cache.find(func_name);
        if (it != cache.end()) return it->second;
        auto dll_it = loaded_dlls.find(L"ole32.dll");
        if (dll_it == loaded_dlls.end()) return 0;
        uint32_t addr = PELoader::ResolveExportName(mem, dll_it->second.pe_info, func_name);
        cache[func_name] = addr;
        return addr;
    };
    Thunk("CoInitializeEx", [this, resolveOle32](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] CoInitializeEx(pMalloc=0x%08X, flags=0x%X)\n", regs[0], regs[1]);
        /* Init native COM for host-side operations */
        CoInitializeEx(NULL, regs[1]);
        /* Forward to ARM ole32 — each real thread has its own COM apartment */
        uint32_t arm_func = resolveOle32(mem, "CoInitializeEx");
        if (arm_func && callback_executor) {
            uint32_t args[2] = { regs[0], regs[1] };
            regs[0] = callback_executor(arm_func, args, 2);
            LOG(API, "[API] CoInitializeEx -> 0x%08X (ARM ole32)\n", regs[0]);
        } else {
            regs[0] = 0; /* S_OK */
        }
        return true;
    });
    Thunk("CoUninitialize", [this, resolveOle32](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] CoUninitialize()\n");
        uint32_t arm_func = resolveOle32(mem, "CoUninitialize");
        if (arm_func && callback_executor) {
            callback_executor(arm_func, nullptr, 0);
        }
        CoUninitialize();
        return true;
    });
    Thunk("CoInitialize", [this, resolveOle32](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] CoInitialize(pvReserved=0x%08X)\n", regs[0]);
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        uint32_t arm_func = resolveOle32(mem, "CoInitialize");
        if (arm_func && callback_executor) {
            uint32_t args[1] = { regs[0] };
            regs[0] = callback_executor(arm_func, args, 1);
            LOG(API, "[API] CoInitialize -> 0x%08X (ARM ole32)\n", regs[0]);
        } else {
            regs[0] = 0;
        }
        return true;
    });
    Thunk("OleInitialize", [this, resolveOle32](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] OleInitialize(pvReserved=0x%08X)\n", regs[0]);
        uint32_t arm_func = resolveOle32(mem, "OleInitialize");
        if (arm_func && callback_executor) {
            uint32_t args[1] = { regs[0] };
            regs[0] = callback_executor(arm_func, args, 1);
            LOG(API, "[API] OleInitialize -> 0x%08X (ARM ole32)\n", regs[0]);
        } else {
            regs[0] = 0;
        }
        return true;
    });
    Thunk("OleUninitialize", [this, resolveOle32](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] OleUninitialize()\n");
        uint32_t arm_func = resolveOle32(mem, "OleUninitialize");
        if (arm_func && callback_executor) {
            callback_executor(arm_func, nullptr, 0);
        }
        return true;
    });
    Thunk("CoCreateInstance", [this, resolveOle32](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* CoCreateInstance(REFCLSID rclsid, IUnknown* pUnkOuter, DWORD dwClsCtx,
                            REFIID riid, void** ppv)
           5 args: R0-R3 + 1 on stack. The 5th arg (ppv) is at the caller's SP. */
        uint32_t rclsid = regs[0], pUnkOuter = regs[1], dwClsCtx = regs[2], riid = regs[3];
        /* 5th arg (ppv) is on the ARM stack */
        uint32_t ppv = ReadStackArg(regs, mem, 0);
        LOG(API, "[API] CoCreateInstance(rclsid=0x%08X, pUnk=0x%08X, ctx=0x%X, riid=0x%08X, ppv=0x%08X)\n",
               rclsid, pUnkOuter, dwClsCtx, riid, ppv);
        uint32_t arm_func = resolveOle32(mem, "CoCreateInstance");
        if (arm_func && callback_executor) {
            uint32_t args[5] = { rclsid, pUnkOuter, dwClsCtx, riid, ppv };
            regs[0] = callback_executor(arm_func, args, 5);
            LOG(API, "[API] CoCreateInstance -> 0x%08X (ARM ole32)\n", regs[0]);
        } else {
            LOG(API, "[API] CoCreateInstance -> E_NOTIMPL (ole32 not loaded)\n");
            regs[0] = 0x80004001; /* E_NOTIMPL */
        }
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
    /* ---- WinCE kernel stubs (moved from misc.cpp for size) ---- */
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
    /* FindFirstChangeNotificationW: real implementation in file.cpp */
    Thunk("FindCloseChangeNotification", 1684, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HANDLE h = (HANDLE)(intptr_t)(int32_t)regs[0];
        BOOL ok = FindCloseChangeNotification(h);
        LOG(API, "[API] FindCloseChangeNotification(0x%08X) -> %d\n", regs[0], ok);
        regs[0] = ok;
        return true;
    });
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
    Thunk("SetSysColors", 890, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* SetSysColors(cElements, lpaElements, lpaRgbValues)
           r0=count, r1=ptr to int array of COLOR_* indices, r2=ptr to COLORREF array */
        int count = (int)regs[0];
        uint32_t pIndices = regs[1];
        uint32_t pColors = regs[2];
        LOG(API, "[API] SetSysColors(count=%d)\n", count);
        if (enable_theming && pIndices && pColors) {
            for (int i = 0; i < count; i++) {
                int idx = (int)mem.Read32(pIndices + i * 4);
                COLORREF color = mem.Read32(pColors + i * 4);
                UpdateWceThemeColor(idx, color);
            }
        }
        regs[0] = 1;
        return true;
    });
    Thunk("GetAsyncKeyState", 826, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)GetAsyncKeyState((int)regs[0]); return true;
    });
    /* Ordinal-only entries */
    ThunkOrdinal("GetOwnerProcess", 606);
    ThunkOrdinal("Random", 80);
}
