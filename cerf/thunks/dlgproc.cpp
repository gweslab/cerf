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
    case WM_NCHITTEST:
    case WM_NCPAINT:
        return FALSE; /* Not handled - let default dialog proc deal with it */
    case WM_NOTIFY:
        /* WM_NOTIFY from ARM commctrl: lParam is a pointer to NMHDR in ARM memory.
           Forward to ARM DlgProc if it's an ARM pointer (fits in 32 bits).
           Native WM_NOTIFY (64-bit pointer) can't be forwarded safely. */
        if (lParam > 0 && (lParam >> 32) == 0)
            break; /* Forward to ARM DlgProc */
        return FALSE;
    }

    auto it = hwnd_dlgproc_map.find(hwnd);
    if (it == hwnd_dlgproc_map.end()) {
        /* During CreateDialogIndirectParamW, WM_INITDIALOG is sent before the
           API returns, so hwnd_dlgproc_map hasn't been populated yet.  Use the
           pending_arm_dlgproc that was stashed before the call. */
        if (msg == WM_INITDIALOG && pending_arm_dlgproc) {
            LOG(API, "[API] EmuDlgProc: WM_INITDIALOG for new HWND=%p using pending_arm_dlgproc=0x%08X\n",
                hwnd, pending_arm_dlgproc);
            hwnd_dlgproc_map[hwnd] = pending_arm_dlgproc;
            it = hwnd_dlgproc_map.find(hwnd);
        } else {
            return FALSE;
        }
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

    if (msg == WM_INITDIALOG) {
        LOG(API, "[API] EmuDlgProc: dispatching WM_INITDIALOG to ARM dlgproc=0x%08X hwnd=%p lParam=0x%X\n",
            arm_dlgproc, hwnd, (uint32_t)lParam);
    }
    uint32_t result = s_instance->callback_executor(arm_dlgproc, args, 4);
    if (msg == WM_NOTIFY && lParam > 0 && (lParam >> 32) == 0) {
        int32_t nmCode = (int32_t)emem.Read32((uint32_t)lParam + 8);
        LONG_PTR msgResult = GetWindowLongPtrW(hwnd, DWLP_MSGRESULT);
        LOG(API, "[API] EmuDlgProc WM_NOTIFY code=%d armResult=%u DWLP_MSGRESULT=0x%lX\n",
            nmCode, result, (unsigned long)msgResult);
    }
    if (msg == WM_INITDIALOG) {
        LOG(API, "[API] EmuDlgProc: WM_INITDIALOG returned %u\n", result);
    }

    /* Copy back results from WM_MEASUREITEM */
    if (msg == WM_MEASUREITEM && lParam) {
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
        mis->itemWidth = emem.Read32(odi_emu_addr + 12);
        mis->itemHeight = emem.Read32(odi_emu_addr + 16);
    }

    /* WM_CTLCOLOR* messages return HBRUSH handles — sign-extend to 64-bit
       so the native window manager gets a valid handle.  Other messages are
       either TRUE/FALSE or small values where sign vs zero extension is moot. */
    return (INT_PTR)(intptr_t)(int32_t)result;
}
