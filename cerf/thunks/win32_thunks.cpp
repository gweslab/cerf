#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <commctrl.h>
#include <shlobj.h>

/* On x64, Windows handles are 32-bit values sign-extended to 64-bit.
   When passing handles from ARM registers to native APIs, we must sign-extend
   (cast through int32_t -> intptr_t) rather than zero-extend (uintptr_t). */

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "imm32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "msimg32.lib")

std::wstring ReadWStringFromEmu(EmulatedMemory& mem, uint32_t addr) {
    if (addr == 0) return L"";
    std::wstring result;
    for (int i = 0; i < 4096; i++) {
        uint16_t ch = mem.Read16(addr + i * 2);
        if (ch == 0) break;
        result += (wchar_t)ch;
    }
    return result;
}

std::string ReadStringFromEmu(EmulatedMemory& mem, uint32_t addr) {
    if (addr == 0) return "";
    std::string result;
    for (int i = 0; i < 4096; i++) {
        uint8_t ch = mem.Read8(addr + i);
        if (ch == 0) break;
        result += (char)ch;
    }
    return result;
}

/* Wrap a native 64-bit HANDLE into a safe 32-bit value for ARM code.
   Uses a mapping table so the handle can be recovered without sign-extension issues. */
uint32_t Win32Thunks::WrapHandle(HANDLE h) {
    if (h == INVALID_HANDLE_VALUE) return (uint32_t)INVALID_HANDLE_VALUE;
    if (h == NULL) return 0;
    uint32_t fake = next_fake_handle++;
    handle_map[fake] = h;
    return fake;
}

HANDLE Win32Thunks::UnwrapHandle(uint32_t fake) {
    if (fake == (uint32_t)INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    if (fake == 0) return NULL;
    auto it = handle_map.find(fake);
    if (it != handle_map.end()) return it->second;
    /* Not in our map — fall back to sign-extension (for handles from other APIs) */
    return (HANDLE)(intptr_t)(int32_t)fake;
}

void Win32Thunks::RemoveHandle(uint32_t fake) {
    handle_map.erase(fake);
}

/* ---- Thunk registration infrastructure ---- */

std::map<uint16_t, std::string> Win32Thunks::ordinal_map;

void Win32Thunks::Thunk(const std::string& name, uint16_t ordinal, ThunkHandler handler) {
    thunk_handlers[name] = std::move(handler);
    if (ordinal > 0)
        ordinal_map[ordinal] = name;
}

void Win32Thunks::Thunk(const std::string& name, ThunkHandler handler) {
    thunk_handlers[name] = std::move(handler);
}

void Win32Thunks::ThunkOrdinal(const std::string& name, uint16_t ordinal) {
    ordinal_map[ordinal] = name;
}

std::string Win32Thunks::ResolveOrdinal(uint16_t ordinal) {
    auto it = ordinal_map.find(ordinal);
    if (it != ordinal_map.end()) return it->second;
    char buf[32];
    sprintf(buf, "ordinal_%d", ordinal);
    return buf;
}

/* ---- Constructor ---- */

Win32Thunks::Win32Thunks(EmulatedMemory& mem)
    : mem(mem), next_thunk_addr(THUNK_BASE), emu_hinstance(0) {
    s_instance = this;
    /* Allocate a memory region for thunk return stubs */
    mem.Alloc(THUNK_BASE, 0x100000);
    /* Register all thunk handlers (map-based dispatch).
       All ordinals go into a single ordinal_map — coredll.dll is the only thunked DLL. */
    RegisterArmRuntimeHandlers();
    RegisterMemoryHandlers();
    RegisterCrtHandlers();
    RegisterStringHandlers();
    RegisterStringFormatHandlers();
    RegisterStringSafeHandlers();
    RegisterGdiDcHandlers();
    RegisterGdiDrawHandlers();
    RegisterGdiTextHandlers();
    /* InitWceSysFont() is deferred — it calls LoadRegistry() which needs
       device_dir, but that isn't set until InitVFS() runs after construction.
       It's called from InitVFS() instead. */
    RegisterGdiRegionHandlers();
    RegisterWindowHandlers();
    RegisterWindowLayoutHandlers();
    RegisterWindowPropsHandlers();
    RegisterDialogHandlers();
    RegisterMessageHandlers();
    RegisterMenuHandlers();
    RegisterInputHandlers();
    RegisterRegistryHandlers();
    RegisterFileHandlers();
    RegisterFileNotifyHandlers();
    RegisterSystemHandlers();
    RegisterSysInfoHandlers();
    RegisterLocaleHandlers();
    RegisterSyncHandlers();
    RegisterResourceHandlers();
    RegisterProcessHandlers();
    RegisterFileMappingHandlers();
    RegisterMiscHandlers();
    RegisterComHandlers();
    RegisterImageListHandlers();
    RegisterModuleHandlers();
    RegisterDpaHandlers();
    RegisterDsaHandlers();
    RegisterStdioHandlers();
    RegisterVfsHandlers();
    RegisterShellHandlers();
    RegisterShellExecHandler();
    /* WinCE UserKData page at fixed address 0xFFFFC800.
       ARM code reads GetCurrentThreadId/GetCurrentProcessId directly from here
       (PUserKData[SH_CURTHREAD] at offset +4, PUserKData[SH_CURPROC] at offset +8).
       Without this, GetCurrentThreadId returns 0 → COMMCTRL g_CriticalSectionOwner
       assert fires on every entry (0 != 0 is false).

       KDataStruct layout (from nkarm.h):
         offset 0x000: lpvTls     — pointer to current thread's TLS slot array
         offset 0x004: ahSys[0]   — SH_WIN32
         offset 0x008: ahSys[1]   — SH_CURTHREAD (current thread handle)
         offset 0x00C: ahSys[2]   — SH_CURPROC (current process handle)

       TLS array layout: 7 pre-TLS DWORDs (negative indices) + 64 TLS slots.
       We place this at 0xFFFFC000 (start of the allocated page).
       lpvTls points to slot 0, which is at 0xFFFFC000 + 7*4 = 0xFFFFC01C. */
    mem.Alloc(0xFFFFC000, 0x1000);
    /* Zero out TLS array area (pre-TLS + 64 slots = 71 DWORDs = 284 bytes) */
    for (uint32_t i = 0; i < 71; i++)
        mem.Write32(0xFFFFC000 + i * 4, 0);
    /* lpvTls → slot 0 of the TLS array */
    uint32_t emu_tls_slots = 0xFFFFC000 + 7 * 4;  /* 0xFFFFC01C */
    mem.Write32(0xFFFFC800 + 0x000, emu_tls_slots);  /* lpvTls */
    mem.Write32(0xFFFFC800 + 0x004, GetCurrentThreadId());  /* ahSys[0] SH_WIN32 (compat) */
    mem.Write32(0xFFFFC800 + 0x008, GetCurrentThreadId());  /* ahSys[1] SH_CURTHREAD */
    mem.Write32(0xFFFFC800 + 0x00C, GetCurrentProcessId()); /* ahSys[2] SH_CURPROC */
    LOG(EMU, "[EMU] KData TLS array at 0x%08X, lpvTls at 0xFFFFC800 -> 0x%08X\n",
        0xFFFFC000, emu_tls_slots);

    /* Register WinCE "Menu" system class — a horizontal menu bar inside CommandBar.
       On real WinCE this is provided by gwes.dll. We implement it with MenuBarWndProc.
       cbWndExtra = 3 pointers: HMENU at 0, hwndNotify at sizeof(LONG_PTR). */
    {
        WNDCLASSEXW wcx = {};
        wcx.cbSize = sizeof(wcx);
        wcx.style = CS_GLOBALCLASS;
        wcx.lpfnWndProc = MenuBarWndProc;
        wcx.hInstance = GetModuleHandleW(NULL);
        wcx.hCursor = LoadCursorW(NULL, IDC_ARROW);
        wcx.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);
        wcx.cbWndExtra = 3 * sizeof(LONG_PTR);
        wcx.lpszClassName = L"Menu";
        ATOM a = RegisterClassExW(&wcx);
        LOG(API, "[API] Pre-register WinCE class 'Menu' -> atom=%d (err=%d)\n",
            a, a ? 0 : GetLastError());
    }
}
