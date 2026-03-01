#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <locale>
#include <codecvt>
#include <commctrl.h>

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

/* Map WinCE paths to host filesystem paths.
   WinCE uses paths like "\skins\file.txt" (root-relative) or "file.txt" (relative).
   We map these relative to the exe directory on the host. */
std::wstring Win32Thunks::MapWinCEPath(const std::wstring& wce_path) {
    if (wce_path.empty()) return wce_path;

    /* Convert exe_dir to wide string */
    std::wstring wide_exe_dir;
    for (char c : exe_dir) wide_exe_dir += (wchar_t)c;

    /* Check if it's already a host absolute path (has drive letter like C:\) */
    if (wce_path.size() >= 2 && wce_path[1] == L':') {
        return wce_path;
    }

    /* WinCE absolute path starting with backslash - strip the leading backslash
       and treat as relative to exe directory */
    if (wce_path[0] == L'\\' || wce_path[0] == L'/') {
        /* Special WinCE paths like \Windows\ - map to exe dir */
        return wide_exe_dir + wce_path.substr(1);
    }

    /* Relative path - prepend exe directory */
    return wide_exe_dir + wce_path;
}

/* Write WIN32_FIND_DATAW to emulated memory using WinCE struct layout.
   WinCE layout (no dwReserved0/1, no cAlternateFileName):
     +0   DWORD  dwFileAttributes
     +4   FILETIME ftCreationTime
     +12  FILETIME ftLastAccessTime
     +20  FILETIME ftLastWriteTime
     +28  DWORD  nFileSizeHigh
     +32  DWORD  nFileSizeLow
     +36  WCHAR  cFileName[MAX_PATH]  (260 wchars = 520 bytes) */
void Win32Thunks::WriteFindDataToEmu(EmulatedMemory& mem, uint32_t addr, const WIN32_FIND_DATAW& fd) {
    mem.Write32(addr + 0, fd.dwFileAttributes);
    mem.Write32(addr + 4, fd.ftCreationTime.dwLowDateTime);
    mem.Write32(addr + 8, fd.ftCreationTime.dwHighDateTime);
    mem.Write32(addr + 12, fd.ftLastAccessTime.dwLowDateTime);
    mem.Write32(addr + 16, fd.ftLastAccessTime.dwHighDateTime);
    mem.Write32(addr + 20, fd.ftLastWriteTime.dwLowDateTime);
    mem.Write32(addr + 24, fd.ftLastWriteTime.dwHighDateTime);
    mem.Write32(addr + 28, fd.nFileSizeHigh);
    mem.Write32(addr + 32, fd.nFileSizeLow);
    /* Write filename at offset 36 */
    for (int i = 0; i < MAX_PATH && fd.cFileName[i]; i++) {
        mem.Write16(addr + 36 + i * 2, fd.cFileName[i]);
    }
    /* Null terminator */
    int len = (int)wcslen(fd.cFileName);
    if (len < MAX_PATH) mem.Write16(addr + 36 + len * 2, 0);
}

/* ---- Emulated Registry (file-backed, text format) ---- */

static std::wstring NarrowToWide(const std::string& s) {
    std::wstring w;
    for (char c : s) w += (wchar_t)(unsigned char)c;
    return w;
}

static std::string WideToNarrow(const std::wstring& w) {
    std::string s;
    for (wchar_t c : w) s += (c < 128) ? (char)c : '?';
    return s;
}

static std::wstring ToLowerW(const std::wstring& s) {
    std::wstring r = s;
    for (auto& c : r) if (c >= L'A' && c <= L'Z') c += 32;
    return r;
}

void Win32Thunks::LoadRegistry() {
    if (registry_loaded) return;
    registry_loaded = true;

    /* Store registry next to cerf.exe, not the WinCE app */
    char cerf_path[MAX_PATH];
    ::GetModuleFileNameA(NULL, cerf_path, MAX_PATH);
    std::string cerf_dir(cerf_path);
    size_t last_sep = cerf_dir.find_last_of("\\/");
    if (last_sep != std::string::npos) cerf_dir = cerf_dir.substr(0, last_sep + 1);
    else cerf_dir = "";
    registry_path = cerf_dir + "cerf_registry.txt";
    printf("[REG] Loading registry from %s\n", registry_path.c_str());

    std::ifstream f(registry_path);
    if (!f.is_open()) {
        printf("[REG] No registry file found, starting empty\n");
        return;
    }

    std::wstring current_key;
    std::string line;
    while (std::getline(f, line)) {
        /* Trim trailing \r */
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        /* Key header: [HKCU\Software\...] */
        if (line[0] == '[' && line.back() == ']') {
            current_key = NarrowToWide(line.substr(1, line.size() - 2));
            registry[current_key]; /* ensure key exists */
            EnsureParentKeys(current_key);
            continue;
        }

        /* Value: "name"=type:data */
        if (current_key.empty() || line[0] != '"') continue;
        size_t eq = line.find("\"=");
        if (eq == std::string::npos || eq < 1) continue;
        std::wstring name = NarrowToWide(line.substr(1, eq - 1));
        std::string rest = line.substr(eq + 2);

        RegValue val = {};
        if (rest.substr(0, 6) == "dword:") {
            val.type = REG_DWORD;
            uint32_t dw = (uint32_t)strtoul(rest.substr(6).c_str(), nullptr, 16);
            val.data.resize(4);
            memcpy(val.data.data(), &dw, 4);
        } else if (rest.substr(0, 3) == "sz:") {
            val.type = REG_SZ;
            std::wstring ws = NarrowToWide(rest.substr(3));
            val.data.resize((ws.size() + 1) * 2);
            memcpy(val.data.data(), ws.c_str(), val.data.size());
        } else if (rest.substr(0, 4) == "hex:") {
            val.type = REG_BINARY;
            std::string hex = rest.substr(4);
            for (size_t i = 0; i < hex.size(); i += 3) {
                val.data.push_back((uint8_t)strtoul(hex.substr(i, 2).c_str(), nullptr, 16));
            }
        }
        registry[current_key].values[name] = val;
    }
    printf("[REG] Loaded %zu keys\n", registry.size());
}

void Win32Thunks::SaveRegistry() {
    if (registry_path.empty()) return;

    std::ofstream f(registry_path);
    if (!f.is_open()) {
        printf("[REG] Failed to save registry to %s\n", registry_path.c_str());
        return;
    }

    for (auto& [path, key] : registry) {
        if (key.values.empty()) continue;
        f << "[" << WideToNarrow(path) << "]\n";
        for (auto& [name, val] : key.values) {
            f << "\"" << WideToNarrow(name) << "\"=";
            if (val.type == REG_DWORD && val.data.size() >= 4) {
                uint32_t dw;
                memcpy(&dw, val.data.data(), 4);
                char buf[16];
                sprintf(buf, "dword:%08X", dw);
                f << buf << "\n";
            } else if (val.type == REG_SZ || val.type == REG_EXPAND_SZ) {
                std::wstring ws((const wchar_t*)val.data.data(), val.data.size() / 2);
                if (!ws.empty() && ws.back() == L'\0') ws.pop_back();
                f << "sz:" << WideToNarrow(ws) << "\n";
            } else {
                f << "hex:";
                for (size_t i = 0; i < val.data.size(); i++) {
                    char buf[4];
                    sprintf(buf, "%s%02X", i > 0 ? "," : "", val.data[i]);
                    f << buf;
                }
                f << "\n";
            }
        }
        f << "\n";
    }
    printf("[REG] Saved %zu keys to %s\n", registry.size(), registry_path.c_str());
}

std::wstring Win32Thunks::ResolveHKey(uint32_t hkey, const std::wstring& subkey) {
    std::wstring root;

    /* Predefined HKEY constants (WinCE uses the same values) */
    if (hkey == 0x80000000) root = L"HKCR";
    else if (hkey == 0x80000001) root = L"HKCU";
    else if (hkey == 0x80000002) root = L"HKLM";
    else if (hkey == 0x80000003) root = L"HKU";
    else {
        /* Look up fake HKEY */
        auto it = hkey_map.find(hkey);
        if (it != hkey_map.end()) root = it->second;
        else root = L"HKCU"; /* fallback */
    }

    if (subkey.empty()) return root;

    /* Strip leading backslash from subkey */
    std::wstring sk = subkey;
    while (!sk.empty() && (sk[0] == L'\\' || sk[0] == L'/')) sk.erase(sk.begin());
    if (sk.empty()) return root;

    /* Normalize separators */
    std::wstring full = root + L"\\" + sk;
    /* Remove trailing backslash */
    while (!full.empty() && full.back() == L'\\') full.pop_back();
    return full;
}

void Win32Thunks::EnsureParentKeys(const std::wstring& path) {
    /* Make sure all parent keys exist and have subkey references */
    size_t pos = 0;
    while ((pos = path.find(L'\\', pos + 1)) != std::wstring::npos) {
        std::wstring parent = path.substr(0, pos);
        std::wstring child_name = path.substr(pos + 1);
        size_t next = child_name.find(L'\\');
        if (next != std::wstring::npos) child_name = child_name.substr(0, next);
        registry[parent].subkeys.insert(child_name);
    }
}

std::map<uint16_t, std::string> Win32Thunks::ordinal_map;

void Win32Thunks::Thunk(const std::string& name, uint16_t ordinal, ThunkHandler handler) {
    thunk_handlers[name] = std::move(handler);
    if (ordinal > 0) ordinal_map[ordinal] = name;
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

std::map<HWND, uint32_t> Win32Thunks::hwnd_wndproc_map;
std::map<UINT_PTR, uint32_t> Win32Thunks::arm_timer_callbacks;
std::map<HWND, uint32_t> Win32Thunks::hwnd_dlgproc_map;
INT_PTR Win32Thunks::modal_dlg_result = 0;
bool Win32Thunks::modal_dlg_ended = false;
Win32Thunks* Win32Thunks::s_instance = nullptr;

INT_PTR CALLBACK Win32Thunks::EmuDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (!s_instance || !s_instance->callback_executor) {
        return FALSE;
    }

    /* Messages with native 64-bit pointers that can't be safely truncated
       to 32 bits for ARM code - let the default dialog proc handle them. */
    switch (msg) {
    case WM_GETMINMAXINFO:
    case WM_NCCALCSIZE:
    case WM_WINDOWPOSCHANGING:
    case WM_WINDOWPOSCHANGED:
    case WM_STYLECHANGING:
    case WM_STYLECHANGED:
    case WM_SETTEXT:
    case WM_GETTEXT:
    case WM_SETICON:
    case WM_NOTIFY:
    case WM_NCHITTEST:
    case WM_NCPAINT:
        return FALSE; /* Not handled - let default dialog proc deal with it */
    }

    auto it = hwnd_dlgproc_map.find(hwnd);
    if (it == hwnd_dlgproc_map.end()) {
        if (msg == WM_INITDIALOG) {
            return FALSE;
        }
        return FALSE;
    }

    uint32_t arm_dlgproc = it->second;

    /* Marshal owner-draw structs from native 64-bit layout to 32-bit ARM layout */
    static uint32_t odi_emu_addr = 0x3F001000;
    EmulatedMemory& emem = s_instance->mem;
    if (!emem.IsValid(odi_emu_addr)) emem.Alloc(odi_emu_addr, 0x1000);

    uint32_t emu_lParam = (uint32_t)lParam;

    if (msg == WM_DRAWITEM && lParam) {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
        /* 32-bit DRAWITEMSTRUCT layout (48 bytes):
           +0  CtlType, +4 CtlID, +8 itemID, +12 itemAction, +16 itemState,
           +20 hwndItem(32), +24 hDC(32), +28 rcItem(16), +44 itemData(32) */
        emem.Write32(odi_emu_addr + 0,  dis->CtlType);
        emem.Write32(odi_emu_addr + 4,  dis->CtlID);
        emem.Write32(odi_emu_addr + 8,  dis->itemID);
        emem.Write32(odi_emu_addr + 12, dis->itemAction);
        emem.Write32(odi_emu_addr + 16, dis->itemState);
        emem.Write32(odi_emu_addr + 20, (uint32_t)(uintptr_t)dis->hwndItem);
        emem.Write32(odi_emu_addr + 24, (uint32_t)(uintptr_t)dis->hDC);
        emem.Write32(odi_emu_addr + 28, dis->rcItem.left);
        emem.Write32(odi_emu_addr + 32, dis->rcItem.top);
        emem.Write32(odi_emu_addr + 36, dis->rcItem.right);
        emem.Write32(odi_emu_addr + 40, dis->rcItem.bottom);
        emem.Write32(odi_emu_addr + 44, (uint32_t)dis->itemData);
        emu_lParam = odi_emu_addr;
    } else if (msg == WM_MEASUREITEM && lParam) {
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
        /* 32-bit MEASUREITEMSTRUCT layout (24 bytes):
           +0 CtlType, +4 CtlID, +8 itemID, +12 itemWidth, +16 itemHeight, +20 itemData(32) */
        emem.Write32(odi_emu_addr + 0,  mis->CtlType);
        emem.Write32(odi_emu_addr + 4,  mis->CtlID);
        emem.Write32(odi_emu_addr + 8,  mis->itemID);
        emem.Write32(odi_emu_addr + 12, mis->itemWidth);
        emem.Write32(odi_emu_addr + 16, mis->itemHeight);
        emem.Write32(odi_emu_addr + 20, (uint32_t)mis->itemData);
        emu_lParam = odi_emu_addr;
    }

    uint32_t args[4] = {
        (uint32_t)(uintptr_t)hwnd,
        (uint32_t)msg,
        (uint32_t)wParam,
        emu_lParam
    };

    uint32_t result = s_instance->callback_executor(arm_dlgproc, args, 4);

    /* Copy back results from WM_MEASUREITEM */
    if (msg == WM_MEASUREITEM && lParam) {
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
        mis->itemWidth = emem.Read32(odi_emu_addr + 12);
        mis->itemHeight = emem.Read32(odi_emu_addr + 16);
    }

    return (INT_PTR)result;
}

LRESULT CALLBACK Win32Thunks::EmuWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (!s_instance || !s_instance->callback_executor) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    auto it = hwnd_wndproc_map.find(hwnd);
    if (it == hwnd_wndproc_map.end()) {
        /* During CreateWindow, HWND is not yet in the map.
           Look up the ARM WndProc from the window class name and auto-register. */
        wchar_t cls_name[256] = {};
        GetClassNameW(hwnd, cls_name, 256);
        auto cls_it = s_instance->arm_wndprocs.find(cls_name);
        if (cls_it != s_instance->arm_wndprocs.end()) {
            hwnd_wndproc_map[hwnd] = cls_it->second;
            it = hwnd_wndproc_map.find(hwnd);
        } else {
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }
    }

    /* Messages with native pointer lParams need marshaling.
       For messages we can't marshal, use DefWindowProcW. */
    LPARAM native_lParam = lParam; /* Save for writeback after ARM callback */
    switch (msg) {
    /* Messages with native 64-bit pointers in wParam/lParam that would be
       corrupted if truncated to 32-bit for the ARM WndProc. Route these
       directly to DefWindowProcW to avoid pointer truncation. */
    case WM_GETMINMAXINFO:      /* lParam = MINMAXINFO* */
    case WM_NCCALCSIZE:         /* lParam = NCCALCSIZE_PARAMS* */
    case WM_WINDOWPOSCHANGING:  /* lParam = WINDOWPOS* */
    case WM_WINDOWPOSCHANGED:   /* lParam = WINDOWPOS* */
    case WM_STYLECHANGING:      /* lParam = STYLESTRUCT* */
    case WM_STYLECHANGED:       /* lParam = STYLESTRUCT* */
    case WM_NCDESTROY:
    case WM_SETTEXT:            /* lParam = LPCWSTR (native pointer) */
    case WM_GETTEXT:            /* lParam = LPWSTR (native buffer) */
    case WM_GETTEXTLENGTH:
    case WM_SETICON:            /* lParam = HICON (64-bit on x64) */
    case WM_GETICON:
    case WM_COPYDATA:           /* lParam = COPYDATASTRUCT* */
    case WM_NOTIFY:             /* lParam = NMHDR* */
    case WM_DELETEITEM:         /* lParam = DELETEITEMSTRUCT* */
    case WM_COMPAREITEM:        /* lParam = COMPAREITEMSTRUCT* */
    case WM_DISPLAYCHANGE:
    case WM_DEVICECHANGE:
    case WM_POWERBROADCAST:
    case WM_INPUT:              /* lParam = HRAWINPUT */
    case WM_NCHITTEST:
    case WM_NCPAINT:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    case WM_CREATE:
    case WM_NCCREATE: {
        /* Marshal CREATESTRUCT into emulated memory (32-bit layout) */
        CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
        static uint32_t cs_emu_addr = 0x3F000000;
        EmulatedMemory& emem = s_instance->mem;
        if (!emem.IsValid(cs_emu_addr)) emem.Alloc(cs_emu_addr, 0x1000);
        emem.Write32(cs_emu_addr + 0,  0);
        emem.Write32(cs_emu_addr + 4,  s_instance->emu_hinstance);
        emem.Write32(cs_emu_addr + 8,  0);
        emem.Write32(cs_emu_addr + 12, (uint32_t)(uintptr_t)cs->hwndParent);
        emem.Write32(cs_emu_addr + 16, cs->cy);
        emem.Write32(cs_emu_addr + 20, cs->cx);
        emem.Write32(cs_emu_addr + 24, cs->y);
        emem.Write32(cs_emu_addr + 28, cs->x);
        emem.Write32(cs_emu_addr + 32, cs->style);
        emem.Write32(cs_emu_addr + 36, 0);
        emem.Write32(cs_emu_addr + 40, 0);
        emem.Write32(cs_emu_addr + 44, cs->dwExStyle);
        lParam = (LPARAM)cs_emu_addr;
        break;
    }
    case WM_DRAWITEM: {
        /* Marshal DRAWITEMSTRUCT into emulated memory (64-bit -> 32-bit) */
        static uint32_t wdi_emu_addr = 0x3F002000;
        EmulatedMemory& emem = s_instance->mem;
        if (!emem.IsValid(wdi_emu_addr)) emem.Alloc(wdi_emu_addr, 0x1000);
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
        emem.Write32(wdi_emu_addr + 0,  dis->CtlType);
        emem.Write32(wdi_emu_addr + 4,  dis->CtlID);
        emem.Write32(wdi_emu_addr + 8,  dis->itemID);
        emem.Write32(wdi_emu_addr + 12, dis->itemAction);
        emem.Write32(wdi_emu_addr + 16, dis->itemState);
        emem.Write32(wdi_emu_addr + 20, (uint32_t)(uintptr_t)dis->hwndItem);
        emem.Write32(wdi_emu_addr + 24, (uint32_t)(uintptr_t)dis->hDC);
        emem.Write32(wdi_emu_addr + 28, dis->rcItem.left);
        emem.Write32(wdi_emu_addr + 32, dis->rcItem.top);
        emem.Write32(wdi_emu_addr + 36, dis->rcItem.right);
        emem.Write32(wdi_emu_addr + 40, dis->rcItem.bottom);
        emem.Write32(wdi_emu_addr + 44, (uint32_t)dis->itemData);
        lParam = (LPARAM)wdi_emu_addr;
        break;
    }
    case WM_MEASUREITEM: {
        /* Marshal MEASUREITEMSTRUCT into emulated memory (64-bit -> 32-bit) */
        static uint32_t wmi_emu_addr = 0x3F002100;
        EmulatedMemory& emem = s_instance->mem;
        if (!emem.IsValid(wmi_emu_addr)) emem.Alloc(wmi_emu_addr, 0x1000);
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
        emem.Write32(wmi_emu_addr + 0,  mis->CtlType);
        emem.Write32(wmi_emu_addr + 4,  mis->CtlID);
        emem.Write32(wmi_emu_addr + 8,  mis->itemID);
        emem.Write32(wmi_emu_addr + 12, mis->itemWidth);
        emem.Write32(wmi_emu_addr + 16, mis->itemHeight);
        emem.Write32(wmi_emu_addr + 20, (uint32_t)mis->itemData);
        lParam = (LPARAM)wmi_emu_addr;
        break;
    }
    }

    uint32_t arm_wndproc = it->second;
    uint32_t args[4] = {
        (uint32_t)(uintptr_t)hwnd,
        (uint32_t)msg,
        (uint32_t)wParam,
        (uint32_t)lParam
    };

    uint32_t result = s_instance->callback_executor(arm_wndproc, args, 4);

    /* Copy back results from WM_MEASUREITEM */
    if (msg == WM_MEASUREITEM && native_lParam) {
        static uint32_t wmi_emu_addr = 0x3F002100;
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)native_lParam;
        EmulatedMemory& emem = s_instance->mem;
        mis->itemWidth = emem.Read32(wmi_emu_addr + 12);
        mis->itemHeight = emem.Read32(wmi_emu_addr + 16);
    }

    return (LRESULT)result;
}

Win32Thunks::Win32Thunks(EmulatedMemory& mem)
    : mem(mem), next_thunk_addr(THUNK_BASE), emu_hinstance(0) {
    s_instance = this;
    /* Allocate a memory region for thunk return stubs */
    mem.Alloc(THUNK_BASE, 0x100000);
    /* Register all thunk handlers (map-based dispatch) */
    RegisterArmRuntimeHandlers();
    RegisterMemoryHandlers();
    RegisterCrtHandlers();
    RegisterStringHandlers();
    RegisterGdiDcHandlers();
    RegisterGdiDrawHandlers();
    RegisterGdiTextHandlers();
    RegisterGdiRegionHandlers();
    RegisterWindowHandlers();
    RegisterWindowPropsHandlers();
    RegisterDialogHandlers();
    RegisterMessageHandlers();
    RegisterMenuHandlers();
    RegisterInputHandlers();
    RegisterRegistryHandlers();
    RegisterFileHandlers();
    RegisterSystemHandlers();
    RegisterResourceHandlers();
    RegisterCommctrlHandlers();
    RegisterCommdlgHandlers();
    RegisterShellHandlers();
    RegisterProcessHandlers();
    RegisterMiscHandlers();
    RegisterModuleHandlers();
    RegisterAygshellHandlers();
    RegisterCeshellHandlers();
}

uint32_t Win32Thunks::AllocThunk(const std::string& dll, const std::string& func,
                                  uint16_t ordinal, bool by_ordinal) {
    uint32_t addr = next_thunk_addr;
    next_thunk_addr += THUNK_STRIDE;

    ThunkEntry entry;
    entry.dll_name = dll;
    entry.func_name = func;
    entry.ordinal = ordinal;
    entry.by_ordinal = by_ordinal;
    entry.thunk_addr = addr;

    thunks[addr] = entry;

    /* Write a recognizable pattern at the thunk address:
       We write a BX LR instruction (0xE12FFF1E in ARM) so if the
       CPU somehow reaches it, it returns. But normally the thunk
       handler intercepts before execution. */
    mem.Write32(addr, 0xE12FFF1E);

    return addr;
}

/* Check if a DLL name refers to a system DLL that we thunk (not an ARM DLL) */
static bool IsThunkedDll(const std::string& dll_name) {
    std::string lower = dll_name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower.find("coredll") != std::string::npos ||
           lower.find("commctrl") != std::string::npos ||
           lower.find("ceshell") != std::string::npos ||
           lower.find("ole32") != std::string::npos ||
           lower.find("aygshell") != std::string::npos;
}

void Win32Thunks::InstallThunks(PEInfo& info) {
    /* First pass: identify and load ARM DLLs that need export resolution.
       Collect unique DLL names that are NOT system DLLs we thunk. */
    std::map<std::string, LoadedDll*> arm_dll_map; /* lowercase dll name -> loaded info */

    for (auto& imp : info.imports) {
        if (IsThunkedDll(imp.dll_name)) continue;

        std::string lower = imp.dll_name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (arm_dll_map.count(lower)) continue; /* Already loaded */

        /* Try to load the ARM DLL */
        std::string dll_path = exe_dir + imp.dll_name;
        FILE* f = fopen(dll_path.c_str(), "rb");
        if (!f) {
            /* Try just the name */
            dll_path = imp.dll_name;
            f = fopen(dll_path.c_str(), "rb");
        }
        if (!f) {
            printf("[THUNK] ARM DLL not found: %s (will use thunk stubs)\n", imp.dll_name.c_str());
            continue;
        }
        fclose(f);

        PEInfo dll_info = {};
        uint32_t entry = PELoader::LoadDll(dll_path.c_str(), mem, dll_info);
        if (entry == 0 && dll_info.image_base == 0) {
            printf("[THUNK] Failed to load ARM DLL: %s\n", dll_path.c_str());
            continue;
        }

        printf("[THUNK] Loaded ARM DLL '%s' at 0x%08X (exports: RVA=0x%X size=0x%X)\n",
               imp.dll_name.c_str(), dll_info.image_base, dll_info.export_rva, dll_info.export_size);

        /* Store in loaded_dlls */
        std::wstring wlower(lower.begin(), lower.end());
        LoadedDll loaded;
        loaded.path = dll_path;
        loaded.base_addr = dll_info.image_base;
        loaded.pe_info = dll_info;
        loaded.native_rsrc_handle = NULL;
        loaded_dlls[wlower] = loaded;

        arm_dll_map[lower] = &loaded_dlls[wlower];

        /* Install thunks for the DLL's own imports (e.g., its COREDLL imports) */
        for (auto& dll_imp : dll_info.imports) {
            uint32_t thunk_addr = AllocThunk(dll_imp.dll_name, dll_imp.func_name,
                                             dll_imp.ordinal, dll_imp.by_ordinal);
            mem.Write32(dll_imp.iat_addr, thunk_addr);
            printf("[THUNK]   DLL import: %s!%s @%d -> thunk 0x%08X\n",
                   dll_imp.dll_name.c_str(),
                   dll_imp.func_name.empty() ? "(ordinal)" : dll_imp.func_name.c_str(),
                   dll_imp.ordinal, thunk_addr);
        }

        /* Queue DLL entry point (DllMain) for deferred call after CPU init */
        if (entry != 0 && dll_info.entry_point_rva != 0) {
            printf("[THUNK]   DLL has entry point at 0x%08X - queued for init\n", entry);
            pending_dll_inits.push_back({entry, dll_info.image_base});
        }
    }

    /* Second pass: install thunks/resolve exports for all imports */
    for (auto& imp : info.imports) {
        std::string lower = imp.dll_name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        /* Check if this import comes from a loaded ARM DLL */
        auto arm_it = arm_dll_map.find(lower);
        if (arm_it != arm_dll_map.end()) {
            /* Resolve the export from the ARM DLL */
            uint32_t arm_addr = 0;
            if (imp.by_ordinal) {
                arm_addr = PELoader::ResolveExportOrdinal(mem, arm_it->second->pe_info, imp.ordinal);
            } else {
                arm_addr = PELoader::ResolveExportName(mem, arm_it->second->pe_info, imp.func_name);
            }

            if (arm_addr != 0) {
                /* Write the actual ARM code address into the IAT */
                mem.Write32(imp.iat_addr, arm_addr);
                if (imp.by_ordinal) {
                    printf("[THUNK] Resolved %s!@%d -> ARM 0x%08X (IAT 0x%08X)\n",
                           imp.dll_name.c_str(), imp.ordinal, arm_addr, imp.iat_addr);
                } else {
                    printf("[THUNK] Resolved %s!%s -> ARM 0x%08X (IAT 0x%08X)\n",
                           imp.dll_name.c_str(), imp.func_name.c_str(), arm_addr, imp.iat_addr);
                }
                continue;
            }
            /* Fall through to thunk if export not found */
            printf("[THUNK] WARNING: Export not found in %s for %s@%d, using thunk stub\n",
                   imp.dll_name.c_str(), imp.func_name.c_str(), imp.ordinal);
        }

        /* System DLL or unresolved - create a thunk */
        uint32_t thunk_addr = AllocThunk(imp.dll_name, imp.func_name, imp.ordinal, imp.by_ordinal);
        mem.Write32(imp.iat_addr, thunk_addr);

        if (imp.by_ordinal) {
            printf("[THUNK] Installed thunk for %s!@%d at 0x%08X -> IAT 0x%08X\n",
                   imp.dll_name.c_str(), imp.ordinal, thunk_addr, imp.iat_addr);
        } else {
            printf("[THUNK] Installed thunk for %s!%s at 0x%08X -> IAT 0x%08X\n",
                   imp.dll_name.c_str(), imp.func_name.c_str(), thunk_addr, imp.iat_addr);
        }
    }
}

void Win32Thunks::CallDllEntryPoints() {
    if (!callback_executor || pending_dll_inits.empty()) return;

    for (auto& init : pending_dll_inits) {
        printf("[THUNK] Calling DllMain at 0x%08X (base=0x%08X, DLL_PROCESS_ATTACH)\n",
               init.entry_point, init.base_addr);
        /* DllMain(hinstDLL, DLL_PROCESS_ATTACH, lpvReserved)
           R0 = hinstDLL (DLL base address)
           R1 = fdwReason = 1 (DLL_PROCESS_ATTACH)
           R2 = lpvReserved = 0 */
        uint32_t args[3] = { init.base_addr, 1, 0 };
        uint32_t result = callback_executor(init.entry_point, args, 3);
        printf("[THUNK] DllMain returned %d\n", result);
    }
    pending_dll_inits.clear();
}

uint32_t Win32Thunks::ReadStackArg(uint32_t* regs, EmulatedMemory& mem, int index) {
    /* ARM calling convention: R0-R3 for first 4 args, then stack.
       index 0 = first stack arg (5th overall arg) */
    uint32_t sp = regs[13];
    return mem.Read32(sp + index * 4);
}

uint32_t Win32Thunks::FindResourceInPE(uint32_t module_base, uint32_t rsrc_rva, uint32_t rsrc_size,
                                       uint32_t type_id, uint32_t name_id,
                                       uint32_t& out_data_rva, uint32_t& out_data_size) {
    if (rsrc_rva == 0 || rsrc_size == 0) return 0;

    uint32_t rsrc_base = module_base + rsrc_rva;

    /* Level 1: Type directory */
    uint16_t num_named = mem.Read16(rsrc_base + 12);
    uint16_t num_id = mem.Read16(rsrc_base + 14);
    uint32_t entry_addr = rsrc_base + 16 + num_named * 8; /* Skip named entries */

    uint32_t type_offset = 0;
    for (uint16_t i = 0; i < num_id; i++) {
        uint32_t id = mem.Read32(entry_addr + i * 8);
        uint32_t off = mem.Read32(entry_addr + i * 8 + 4);
        if (id == type_id && (off & 0x80000000)) {
            type_offset = off & 0x7FFFFFFF;
            break;
        }
    }
    if (type_offset == 0) return 0;

    /* Level 2: Name/ID directory */
    uint32_t name_dir = rsrc_base + type_offset;
    num_named = mem.Read16(name_dir + 12);
    num_id = mem.Read16(name_dir + 14);
    entry_addr = name_dir + 16 + num_named * 8;

    uint32_t name_offset = 0;
    for (uint16_t i = 0; i < num_id; i++) {
        uint32_t id = mem.Read32(entry_addr + i * 8);
        uint32_t off = mem.Read32(entry_addr + i * 8 + 4);
        if (id == name_id) {
            if (off & 0x80000000) {
                name_offset = off & 0x7FFFFFFF;
            } else {
                /* Direct data entry */
                uint32_t data_entry = rsrc_base + off;
                out_data_rva = mem.Read32(data_entry);
                out_data_size = mem.Read32(data_entry + 4);
                return 1;
            }
            break;
        }
    }
    if (name_offset == 0) return 0;

    /* Level 3: Language directory - just take the first entry */
    uint32_t lang_dir = rsrc_base + name_offset;
    num_named = mem.Read16(lang_dir + 12);
    num_id = mem.Read16(lang_dir + 14);
    uint32_t total = num_named + num_id;
    if (total == 0) return 0;

    entry_addr = lang_dir + 16;
    uint32_t off = mem.Read32(entry_addr + 4);
    if (off & 0x80000000) return 0; /* Should be a leaf */

    uint32_t data_entry = rsrc_base + off;
    out_data_rva = mem.Read32(data_entry);
    out_data_size = mem.Read32(data_entry + 4);
    return 1;
}

HMODULE Win32Thunks::GetNativeModuleForResources(uint32_t emu_handle) {
    /* Check loaded ARM DLLs */
    for (auto& pair : loaded_dlls) {
        if (pair.second.base_addr == emu_handle) {
            if (!pair.second.native_rsrc_handle) {
                pair.second.native_rsrc_handle = LoadLibraryExA(
                    pair.second.path.c_str(), NULL,
                    LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            }
            return pair.second.native_rsrc_handle;
        }
    }
    /* Check main exe */
    if (emu_handle == emu_hinstance) {
        static HMODULE exe_rsrc = NULL;
        if (!exe_rsrc) {
            std::string narrow_exe;
            for (auto c : exe_path) narrow_exe += (char)c;
            exe_rsrc = LoadLibraryExA(narrow_exe.c_str(), NULL,
                LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        }
        return exe_rsrc;
    }
    return NULL;
}

bool Win32Thunks::HandleThunk(uint32_t addr, uint32_t* regs, EmulatedMemory& mem) {
    /* Check if address is in thunk range */
    auto it = thunks.find(addr);
    if (it == thunks.end()) {
        /* Also check addr+1 for Thumb calls */
        it = thunks.find(addr & ~1u);
        if (it == thunks.end()) {
            /* Handle WinCE trap-based API calls (0xF000xxxx range).
               WinCE apps call some APIs via trap addresses descending from 0xF0010000.
               API index = (0xF0010000 - addr) / 4, which maps to COREDLL ordinals. */
            if (addr >= WINCE_TRAP_BASE && addr < WINCE_TRAP_TOP) {
                uint32_t api_index = (WINCE_TRAP_TOP - addr) / 4;
                auto name_it = ordinal_map.find((uint16_t)api_index);
                std::string func_name = (name_it != ordinal_map.end()) ? name_it->second : "";
                if (!func_name.empty()) {
                    printf("[THUNK] WinCE trap 0x%08X -> API %u (%s)\n", addr, api_index, func_name.c_str());
                } else {
                    printf("[THUNK] WinCE trap 0x%08X -> API %u (unknown)\n", addr, api_index);
                }
                /* Create a temporary thunk entry and execute it */
                ThunkEntry trap_entry;
                trap_entry.dll_name = "COREDLL.dll";
                trap_entry.func_name = func_name;
                trap_entry.ordinal = (uint16_t)api_index;
                trap_entry.by_ordinal = true;
                trap_entry.thunk_addr = addr;
                bool result = ExecuteThunk(trap_entry, regs, mem);
                if (result) {
                    uint32_t lr = regs[14];
                    regs[15] = (lr & 1) ? (lr & ~1u) : (lr & ~3u);
                }
                return result;
            }

            /* Detect branches into thunk memory region at unregistered addresses */
            if (addr >= THUNK_BASE && addr < THUNK_BASE + 0x100000) {
                printf("[EMU] ERROR: Branch to unregistered thunk address 0x%08X (LR=0x%08X)\n",
                       addr, regs[14]);
                regs[0] = 0;
                uint32_t lr = regs[14];
                regs[15] = (lr & 1) ? (lr & ~1u) : (lr & ~3u);
                return true;
            }
            return false;
        }
    }

    bool result = ExecuteThunk(it->second, regs, mem);
    if (result) {
        /* Return to caller: set PC = LR */
        uint32_t lr = regs[14];
        if (lr & 1) {
            /* Return to Thumb mode */
            regs[15] = lr & ~1u;
            /* Keep Thumb flag - handled by caller */
        } else {
            regs[15] = lr & ~3u;
        }
    }
    return result;
}

bool Win32Thunks::ExecuteThunk(const ThunkEntry& entry, uint32_t* regs, EmulatedMemory& mem) {
    std::string func = entry.func_name;
    if (func.empty() && entry.by_ordinal) {
        func = ResolveOrdinal(entry.ordinal);
        if (!func.empty()) {
            printf("[THUNK] Resolved ordinal %d -> %s\n", entry.ordinal, func.c_str());
        }
    }

    /* Map-based dispatch: look up handler by function name */
    auto it = thunk_handlers.find(func);
    if (it != thunk_handlers.end()) return it->second(regs, mem);

    /* CEShell.DLL generic fallback */
    if (entry.dll_name == "CEShell.DLL" || entry.dll_name == "ceshell.dll") {
        regs[0] = 0;
        printf("[THUNK] ceshell.dll!%s (ordinal %d) -> 0 (stub)\n",
               func.empty() ? "(unknown)" : func.c_str(), entry.ordinal);
        return true;
    }

    /* commctrl.dll stubs */
    if (entry.dll_name == "commctrl.dll" || entry.dll_name == "COMMCTRL.DLL") {
        regs[0] = 1;
        printf("[THUNK] commctrl.dll!%s (ordinal %d) -> 1 (stub)\n",
               func.empty() ? "(unknown)" : func.c_str(), entry.ordinal);
        return true;
    }

    /* ole32.dll stubs */
    if (entry.dll_name == "ole32.dll" || entry.dll_name == "OLE32.DLL") {
        regs[0] = 0; /* S_OK */
        printf("[THUNK] ole32.dll!%s -> S_OK (stub)\n",
               func.empty() ? "(unknown)" : func.c_str());
        return true;
    }

    /* aygshell.dll stubs - WinCE Shell Helper Library */
    if (entry.dll_name == "aygshell.dll" || entry.dll_name == "AYGSHELL.DLL" ||
        entry.dll_name == "aygshell" || entry.dll_name == "AYGSHELL") {
        regs[0] = 0;
        printf("[THUNK] aygshell.dll!%s (ordinal %d) -> 0 (stub)\n",
               func.empty() ? "(unknown)" : func.c_str(), entry.ordinal);
        return true;
    }

    /* Unhandled function */
    if (!func.empty()) {
        printf("[THUNK] UNHANDLED: %s!%s (ordinal=%d) - returning 0\n",
               entry.dll_name.c_str(), func.c_str(), entry.ordinal);
    } else if (entry.by_ordinal) {
        printf("[THUNK] UNHANDLED: %s!@%d (no name mapping) - returning 0\n",
               entry.dll_name.c_str(), entry.ordinal);
    } else {
        printf("[THUNK] UNHANDLED: %s!%s - returning 0\n",
               entry.dll_name.c_str(), entry.func_name.c_str());
    }
    regs[0] = 0;
    return true;
}
