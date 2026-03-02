#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"

/* WinCE "Menu" system class — renders a horizontal menu bar inside CommandBar.
   On real WinCE this is provided by gwes.dll. We implement it natively.
   Window extra bytes: GWL(0)=HMENU, GWL(4)=hwndNotify, GWL(8)=item_count */
LRESULT CALLBACK Win32Thunks::MenuBarWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_NCCREATE: {
        CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
        /* lpCreateParams is the ARM address of MENUCONTROLINFO:
           +0 hinst(32), +4 lpszMenuName(32), +8 hwndNotify(32) */
        uint32_t mci_addr = (uint32_t)(uintptr_t)cs->lpCreateParams;
        LOG(THUNK, "[THUNK] Menu WM_NCCREATE: lpCreateParams=0x%08X\n", mci_addr);
        if (mci_addr && s_instance) {
            EmulatedMemory& emem = s_instance->mem;
            uint32_t hinst = emem.Read32(mci_addr + 0);
            uint32_t menu_name = emem.Read32(mci_addr + 4);
            uint32_t notify_hwnd = emem.Read32(mci_addr + 8);
            LOG(THUNK, "[THUNK] Menu MCI: hinst=0x%08X, menuName=0x%08X, notify=0x%08X\n",
                hinst, menu_name, notify_hwnd);
            SetWindowLongPtrW(hwnd, sizeof(LONG_PTR), (LONG_PTR)(intptr_t)(int32_t)notify_hwnd);
            HMENU hMenu = NULL;
            if (hinst == 0 && menu_name != 0) {
                /* hinst=NULL, pszMenu=HMENU: use existing menu handle directly */
                hMenu = (HMENU)(intptr_t)(int32_t)menu_name;
                LOG(THUNK, "[THUNK] Menu WM_NCCREATE: using HMENU 0x%p directly\n", hMenu);
            } else {
                /* Load menu from module resources */
                if (hinst == 0) hinst = s_instance->emu_hinstance;
                HMODULE native_mod = s_instance->GetNativeModuleForResources(hinst);
                if (native_mod && menu_name) {
                    hMenu = LoadMenuW(native_mod, MAKEINTRESOURCEW(menu_name));
                    LOG(THUNK, "[THUNK] Menu WM_NCCREATE: LoadMenuW(0x%08X, %d) -> 0x%p (err=%d)\n",
                        hinst, menu_name, hMenu, hMenu ? 0 : GetLastError());
                } else if (!native_mod && menu_name) {
                    LOG(THUNK, "[THUNK] Menu WM_NCCREATE: no native module for hinst=0x%08X\n", hinst);
                }
            }
            if (hMenu) SetWindowLongPtrW(hwnd, 0, (LONG_PTR)hMenu);
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    case WM_CREATE: {
        /* Size window to fit menu items */
        HMENU hMenu = (HMENU)GetWindowLongPtrW(hwnd, 0);
        if (hMenu) {
            int count = GetMenuItemCount(hMenu);
            HDC hdc = GetDC(hwnd);
            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            HFONT hOld = (HFONT)SelectObject(hdc, hFont);
            int total_width = 0;
            for (int i = 0; i < count; i++) {
                wchar_t text[128] = {};
                GetMenuStringW(hMenu, i, text, 128, MF_BYPOSITION);
                SIZE sz;
                GetTextExtentPoint32W(hdc, text, (int)wcslen(text), &sz);
                total_width += sz.cx + 12; /* padding between items */
            }
            SelectObject(hdc, hOld);
            ReleaseDC(hwnd, hdc);
            LOG(THUNK, "[THUNK] Menu WM_CREATE: %d items, total_width=%d\n", count, total_width);
            if (total_width > 0) {
                CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
                SetWindowPos(hwnd, NULL, 0, 0, total_width, cs->cy, SWP_NOMOVE | SWP_NOZORDER);
            }
        }
        return 0;
    }
    case WM_SIZE: {
        RECT wr; GetWindowRect(hwnd, &wr);
        LOG(THUNK, "[THUNK] Menu WM_SIZE: type=%d new_client=%dx%d window=%dx%d\n",
            (int)wParam, LOWORD(lParam), HIWORD(lParam),
            wr.right-wr.left, wr.bottom-wr.top);
        break;
    }
    case WM_WINDOWPOSCHANGED: {
        WINDOWPOS* wp = (WINDOWPOS*)lParam;
        if (wp) {
            LOG(THUNK, "[THUNK] Menu WM_WINDOWPOSCHANGED: x=%d y=%d cx=%d cy=%d flags=0x%04X\n",
                wp->x, wp->y, wp->cx, wp->cy, wp->flags);
        }
        break;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        HMENU hMenu = (HMENU)GetWindowLongPtrW(hwnd, 0);
        if (hMenu) {
            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            HFONT hOld = (HFONT)SelectObject(hdc, hFont);
            SetBkMode(hdc, TRANSPARENT);
            RECT client;
            GetClientRect(hwnd, &client);
            /* Fill background with button face color */
            FillRect(hdc, &client, GetSysColorBrush(COLOR_BTNFACE));
            int count = GetMenuItemCount(hMenu);
            int x = 0;
            for (int i = 0; i < count; i++) {
                wchar_t text[128] = {};
                GetMenuStringW(hMenu, i, text, 128, MF_BYPOSITION);
                SIZE sz;
                GetTextExtentPoint32W(hdc, text, (int)wcslen(text), &sz);
                RECT item_rc = { x + 4, client.top, x + sz.cx + 12, client.bottom };
                DrawTextW(hdc, text, -1, &item_rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                x += sz.cx + 12;
            }
            SelectObject(hdc, hOld);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_LBUTTONDOWN: {
        HMENU hMenu = (HMENU)GetWindowLongPtrW(hwnd, 0);
        HWND hwndNotify = (HWND)GetWindowLongPtrW(hwnd, sizeof(LONG_PTR));
        if (!hMenu) break;
        int mx = LOWORD(lParam);
        /* Hit-test which menu item was clicked */
        HDC hdc = GetDC(hwnd);
        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HFONT hOld = (HFONT)SelectObject(hdc, hFont);
        int count = GetMenuItemCount(hMenu);
        int x = 0, hit = -1, hit_x = 0;
        for (int i = 0; i < count; i++) {
            wchar_t text[128] = {};
            GetMenuStringW(hMenu, i, text, 128, MF_BYPOSITION);
            SIZE sz;
            GetTextExtentPoint32W(hdc, text, (int)wcslen(text), &sz);
            if (mx >= x && mx < x + sz.cx + 12) { hit = i; hit_x = x; break; }
            x += sz.cx + 12;
        }
        SelectObject(hdc, hOld);
        ReleaseDC(hwnd, hdc);
        if (hit >= 0) {
            HMENU hSub = GetSubMenu(hMenu, hit);
            if (hSub) {
                RECT rc;
                GetWindowRect(hwnd, &rc);
                int popup_x = rc.left + hit_x;
                int popup_y = rc.bottom;
                /* Use TPM_RETURNCMD | TPM_NONOTIFY to avoid sending menu
                   notifications to the ARM WndProc which can't handle them.
                   Use the Menu window as owner to keep things simple. */
                UINT cmd = (UINT)TrackPopupMenuEx(hSub,
                    TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD | TPM_NONOTIFY,
                    popup_x, popup_y, hwnd, NULL);
                if (cmd) {
                    HWND notify = hwndNotify ? hwndNotify : GetParent(hwnd);
                    if (notify)
                        PostMessageW(notify, WM_COMMAND, MAKEWPARAM(cmd, 0), 0);
                }
            }
        }
        return 0;
    }
    case WM_DESTROY: {
        HMENU hMenu = (HMENU)GetWindowLongPtrW(hwnd, 0);
        if (hMenu) DestroyMenu(hMenu);
        SetWindowLongPtrW(hwnd, 0, 0);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}
