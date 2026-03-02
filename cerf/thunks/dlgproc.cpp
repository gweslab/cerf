#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"

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
