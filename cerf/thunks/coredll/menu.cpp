/* Menu thunks: Create, Append, Enable, Check, Track, Load */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterMenuHandlers() {
    Thunk("CreateMenu", 851, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreateMenu(); return true;
    });
    Thunk("CreatePopupMenu", 852, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreatePopupMenu(); return true;
    });
    Thunk("DestroyMenu", 844, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HMENU h = (HMENU)(intptr_t)(int32_t)regs[0];
        BOOL ok = DestroyMenu(h);
        LOG(API, "[API] DestroyMenu(0x%p) -> %d err=%lu\n", h, ok, ok ? 0 : GetLastError());
        regs[0] = ok; return true;
    });
    Thunk("GetSubMenu", 855, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HMENU h = (HMENU)(intptr_t)(int32_t)regs[0];
        HMENU sub = GetSubMenu(h, regs[1]);
        LOG(API, "[API] GetSubMenu(0x%p, %d) -> 0x%p (trunc=0x%08X)\n", h, regs[1], sub, (uint32_t)(uintptr_t)sub);
        regs[0] = (uint32_t)(uintptr_t)sub; return true;
    });
    Thunk("AppendMenuW", 842, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* MF_STRING is 0x0, so can't test with bitwise AND.
           A menu item has a string if none of MF_OWNERDRAW/MF_BITMAP/MF_SEPARATOR are set. */
        bool is_string = regs[3] != 0 && !(regs[1] & (MF_OWNERDRAW | MF_BITMAP | MF_SEPARATOR));
        std::wstring text;
        if (is_string) text = ReadWStringFromEmu(mem, regs[3]);
        LOG(API, "[API] AppendMenuW(hMenu=0x%08X, flags=0x%X, id=0x%X, str=%ls)\n",
            regs[0], regs[1], regs[2], is_string ? text.c_str() : L"(non-string)");
        regs[0] = AppendMenuW((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2],
            is_string ? text.c_str() : (LPCWSTR)(uintptr_t)regs[3]);
        return true;
    });
    Thunk("EnableMenuItem", 847, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = EnableMenuItem((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2]); return true;
    });
    Thunk("CheckMenuItem", 848, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = CheckMenuItem((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2]); return true;
    });
    Thunk("CheckMenuRadioItem", 849, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = CheckMenuRadioItem((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs, mem, 0));
        return true;
    });
    Thunk("GetMenuState", 843, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetMenuState((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2]); return true;
    });
    Thunk("GetMenuItemCount", 888, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)GetMenuItemCount((HMENU)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("DrawMenuBar", 856, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DrawMenuBar((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("SetAssociatedMenu", 299, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] SetAssociatedMenu(hwnd=0x%08X, hmenu=0x%08X) -> stub\n", regs[0], regs[1]);
        regs[0] = 0; return true;
    });
    Thunk("LoadMenuW", 846, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t hmod = regs[0];
        bool is_arm = (hmod == emu_hinstance || hmod == 0);
        if (!is_arm) {
            for (auto& pair : loaded_dlls) {
                if (pair.second.base_addr == hmod) { is_arm = true; break; }
            }
        }
        HMODULE native_mod = NULL;
        if (is_arm) {
            uint32_t h = (hmod == 0) ? emu_hinstance : hmod;
            native_mod = GetNativeModuleForResources(h);
        } else {
            native_mod = (HMODULE)(intptr_t)(int32_t)hmod;
        }
        HMENU hMenu = native_mod ? LoadMenuW(native_mod, MAKEINTRESOURCEW(regs[1])) : NULL;
        LOG(API, "[API] LoadMenuW(0x%08X, %d) -> 0x%p%s\n",
            hmod, regs[1], hMenu, is_arm ? " (ARM)" : "");
        regs[0] = (uint32_t)(uintptr_t)hMenu;
        return true;
    });
    Thunk("TrackPopupMenuEx", 845, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HMENU hMenu = (HMENU)(intptr_t)(int32_t)regs[0];
        UINT flags = regs[1];
        int x = (int)regs[2], y = (int)regs[3];
        HWND hwnd = (HWND)(intptr_t)(int32_t)ReadStackArg(regs, mem, 0);
        /* Mask off WinCE-specific high bits (0x10000000 etc.) that are invalid on desktop */
        flags &= 0x0000FFFF;
        int count = GetMenuItemCount(hMenu);
        LOG(API, "[API] TrackPopupMenuEx(hMenu=0x%p items=%d, flags=0x%X, x=%d, y=%d, hwnd=0x%p)\n",
            hMenu, count, flags, x, y, hwnd);
        regs[0] = TrackPopupMenuEx(hMenu, flags, x, y, hwnd, NULL);
        LOG(API, "[API] TrackPopupMenuEx -> %d\n", regs[0]);
        return true;
    });
    Thunk("InsertMenuW", 841, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HMENU hMenu = (HMENU)(intptr_t)(int32_t)regs[0];
        UINT uPosition = regs[1], uFlags = regs[2], uIDNewItem = regs[3];
        uint32_t lpNewItem = ReadStackArg(regs, mem, 0);
        LPCWSTR str = NULL;
        std::wstring text;
        /* MF_STRING is 0x0 — check for absence of special type flags instead */
        bool is_string = lpNewItem != 0 && !(uFlags & (MF_OWNERDRAW | MF_BITMAP | MF_SEPARATOR));
        if (is_string) {
            text = ReadWStringFromEmu(mem, lpNewItem);
            str = text.c_str();
        }
        LOG(API, "[API] InsertMenuW(hMenu=0x%p, pos=%d, flags=0x%X, id=0x%X, str=%ls)\n",
            hMenu, uPosition, uFlags, uIDNewItem, is_string ? str : L"(non-string)");
        regs[0] = InsertMenuW(hMenu, uPosition, uFlags, uIDNewItem,
            is_string ? str : (LPCWSTR)(uintptr_t)lpNewItem);
        return true;
    });
    Thunk("DeleteMenu", 850, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DeleteMenu((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2]);
        return true;
    });
    /* SetMenuItemInfoW — WinCE MENUITEMINFOW is 44 bytes (32-bit pointers):
       +0 cbSize, +4 fMask, +8 fType, +12 fState, +16 wID,
       +20 hSubMenu(32), +24 hbmpChecked(32), +28 hbmpUnchecked(32),
       +32 dwItemData(32), +36 dwTypeData(32), +40 cch */
    Thunk("SetMenuItemInfoW", 853, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HMENU hMenu = (HMENU)(intptr_t)(int32_t)regs[0];
        UINT uItem = regs[1];
        BOOL fByPosition = regs[2];
        uint32_t pMii = regs[3];
        MENUITEMINFOW mii = {};
        mii.cbSize = sizeof(MENUITEMINFOW);
        mii.fMask = mem.Read32(pMii + 4);
        mii.fType = mem.Read32(pMii + 8);
        mii.fState = mem.Read32(pMii + 12);
        mii.wID = mem.Read32(pMii + 16);
        mii.hSubMenu = (HMENU)(intptr_t)(int32_t)mem.Read32(pMii + 20);
        mii.hbmpChecked = (HBITMAP)(intptr_t)(int32_t)mem.Read32(pMii + 24);
        mii.hbmpUnchecked = (HBITMAP)(intptr_t)(int32_t)mem.Read32(pMii + 28);
        mii.dwItemData = mem.Read32(pMii + 32);
        std::wstring text;
        uint32_t typeData = mem.Read32(pMii + 36);
        if ((mii.fMask & MIIM_STRING) || ((mii.fMask & MIIM_TYPE) && !(mii.fType & MFT_SEPARATOR))) {
            if (typeData) {
                text = ReadWStringFromEmu(mem, typeData);
                mii.dwTypeData = const_cast<LPWSTR>(text.c_str());
                mii.cch = (UINT)text.size();
            }
        }
        BOOL ret = SetMenuItemInfoW(hMenu, uItem, fByPosition, &mii);
        LOG(API, "[API] SetMenuItemInfoW(0x%08X, %u, %d) -> %d\n",
            (uint32_t)(uintptr_t)hMenu, uItem, fByPosition, ret);
        regs[0] = ret;
        return true;
    });
    /* GetMenuItemInfoW — reverse of SetMenuItemInfoW.
       WinCE MENUITEMINFOW is 44 bytes (same layout as above). */
    Thunk("GetMenuItemInfoW", 854, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HMENU hMenu = (HMENU)(intptr_t)(int32_t)regs[0];
        UINT uItem = regs[1];
        BOOL fByPosition = regs[2];
        uint32_t pMii = regs[3];
        uint32_t fMask = mem.Read32(pMii + 4);
        uint32_t typeDataPtr = mem.Read32(pMii + 36);
        uint32_t cch = mem.Read32(pMii + 40);
        MENUITEMINFOW mii = {};
        mii.cbSize = sizeof(MENUITEMINFOW);
        mii.fMask = fMask;
        wchar_t textBuf[512] = {};
        bool want_string = (fMask & (MIIM_STRING | MIIM_TYPE)) != 0;
        if (want_string && typeDataPtr && cch > 0) {
            mii.dwTypeData = textBuf;
            mii.cch = min((uint32_t)511, cch);
        }
        BOOL ret = GetMenuItemInfoW(hMenu, uItem, fByPosition, &mii);
        LOG(API, "[API] GetMenuItemInfoW(0x%08X, %u, %d, mask=0x%X) -> %d\n",
            (uint32_t)(uintptr_t)hMenu, uItem, fByPosition, fMask, ret);
        if (ret) {
            if (fMask & MIIM_TYPE)       mem.Write32(pMii + 8,  mii.fType);
            if (fMask & MIIM_STATE)      mem.Write32(pMii + 12, mii.fState);
            if (fMask & MIIM_ID)         mem.Write32(pMii + 16, mii.wID);
            if (fMask & MIIM_SUBMENU)    mem.Write32(pMii + 20, (uint32_t)(uintptr_t)mii.hSubMenu);
            if (fMask & MIIM_CHECKMARKS) {
                mem.Write32(pMii + 24, (uint32_t)(uintptr_t)mii.hbmpChecked);
                mem.Write32(pMii + 28, (uint32_t)(uintptr_t)mii.hbmpUnchecked);
            }
            if (fMask & MIIM_DATA)       mem.Write32(pMii + 32, (uint32_t)mii.dwItemData);
            if (fMask & MIIM_STRING)     mem.Write32(pMii + 8,  mii.fType);
            if (want_string && typeDataPtr && cch > 0 && mii.dwTypeData) {
                uint32_t len = (uint32_t)wcslen(textBuf);
                uint32_t copyLen = min(len, cch - 1);
                for (uint32_t i = 0; i < copyLen; i++)
                    mem.Write16(typeDataPtr + i * 2, textBuf[i]);
                mem.Write16(typeDataPtr + copyLen * 2, 0);
                mem.Write32(pMii + 40, len);
            } else if (want_string) {
                mem.Write32(pMii + 40, mii.cch);
            }
        }
        regs[0] = ret;
        return true;
    });
}
