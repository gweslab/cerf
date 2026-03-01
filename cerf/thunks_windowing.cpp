/* Win32 thunks: window management, messages, input, dialogs, menus */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include <cstdio>
#include <algorithm>
#include <commctrl.h>
#include <vector>

/* Helper: compute size of a DLGTEMPLATE (with all items) in emulated memory. */
static uint32_t ComputeDlgTemplateSize(EmulatedMemory& mem, uint32_t addr) {
    uint32_t p = addr;
    uint16_t cdit = mem.Read16(p + 8);
    p += 18;

    uint16_t w = mem.Read16(p);
    if (w == 0x0000) { p += 2; }
    else if (w == 0xFFFF) { p += 4; }
    else { while (mem.Read16(p)) p += 2; p += 2; }

    w = mem.Read16(p);
    if (w == 0x0000) { p += 2; }
    else if (w == 0xFFFF) { p += 4; }
    else { while (mem.Read16(p)) p += 2; p += 2; }

    while (mem.Read16(p)) p += 2; p += 2;

    uint32_t style = mem.Read32(addr);
    if (style & DS_SETFONT) {
        p += 2;
        while (mem.Read16(p)) p += 2; p += 2;
    }

    for (int i = 0; i < cdit; i++) {
        p = (p + 3) & ~3u;
        p += 18;

        w = mem.Read16(p);
        if (w == 0xFFFF) { p += 4; }
        else { while (mem.Read16(p)) p += 2; p += 2; }

        w = mem.Read16(p);
        if (w == 0xFFFF) { p += 4; }
        else { while (mem.Read16(p)) p += 2; p += 2; }

        uint16_t extra = mem.Read16(p);
        p += 2 + extra;
    }

    return p - addr;
}

static std::vector<uint8_t> CopyDlgTemplate(EmulatedMemory& mem, uint32_t addr) {
    uint32_t size = ComputeDlgTemplateSize(mem, addr);
    std::vector<uint8_t> buf(size);
    for (uint32_t i = 0; i < size; i++) {
        buf[i] = mem.Read8(addr + i);
    }
    return buf;
}

bool Win32Thunks::ExecuteWindowThunk(const std::string& func, uint32_t* regs, EmulatedMemory& mem) {
    /* RegisterClassW */
    if (func == "RegisterClassW") {
        uint32_t arm_wndproc = mem.Read32(regs[0] + 4);
        WNDCLASSW wc = {};
        wc.style = mem.Read32(regs[0]);
        wc.lpfnWndProc = EmuWndProc;
        wc.cbClsExtra = mem.Read32(regs[0] + 8);
        wc.cbWndExtra = mem.Read32(regs[0] + 12);
        wc.hInstance = GetModuleHandleW(NULL);
        wc.hIcon = (HICON)(intptr_t)(int32_t)mem.Read32(regs[0] + 20);
        wc.hCursor = (HCURSOR)(intptr_t)(int32_t)mem.Read32(regs[0] + 24);
        wc.hbrBackground = (HBRUSH)(intptr_t)(int32_t)mem.Read32(regs[0] + 28);
        uint32_t name_addr = mem.Read32(regs[0] + 36);
        std::wstring className = ReadWStringFromEmu(mem, name_addr);
        wc.lpszClassName = className.c_str();

        arm_wndprocs[className] = arm_wndproc;

        printf("[THUNK] RegisterClassW: '%ls' (ARM WndProc=0x%08X)\n",
               className.c_str(), arm_wndproc);

        ATOM atom = RegisterClassW(&wc);
        regs[0] = (uint32_t)atom;
        return true;
    }

    if (func == "CreateWindowExW") {
        uint32_t exStyle = regs[0];
        std::wstring className = ReadWStringFromEmu(mem, regs[1]);
        std::wstring windowName = ReadWStringFromEmu(mem, regs[2]);
        uint32_t style = regs[3];
        int x = (int)ReadStackArg(regs, mem, 0);
        int y = (int)ReadStackArg(regs, mem, 1);
        int w = (int)ReadStackArg(regs, mem, 2);
        int h = (int)ReadStackArg(regs, mem, 3);
        HWND parent = (HWND)(intptr_t)(int32_t)ReadStackArg(regs, mem, 4);
        HMENU menu_h = (HMENU)(intptr_t)(int32_t)ReadStackArg(regs, mem, 5);

        exStyle &= 0x0FFFFFFF;

        bool is_toplevel = (parent == NULL && !(style & WS_CHILD));
        if (is_toplevel) {
            RECT work_area;
            SystemParametersInfoW(SPI_GETWORKAREA, 0, &work_area, 0);
            int bw = GetSystemMetrics(SM_CXBORDER);
            int bh = GetSystemMetrics(SM_CYBORDER);
            x = work_area.left - bw;
            y = work_area.top - bh;
            w = (work_area.right - work_area.left) + bw * 2;
            h = (work_area.bottom - work_area.top) + bh * 2;
            exStyle |= WS_EX_APPWINDOW;
        } else {
            if (x == (int)0x80000000) x = CW_USEDEFAULT;
            if (y == (int)0x80000000) y = CW_USEDEFAULT;
            if (w == (int)0x80000000 || w == 0) w = 320;
            if (h == (int)0x80000000 || h == 0) h = 240;
        }

        printf("[THUNK] CreateWindowExW: class='%ls' title='%ls' style=0x%08X exStyle=0x%08X size=(%dx%d)\n",
               className.c_str(), windowName.c_str(), style, exStyle, w, h);

        HWND hwnd = CreateWindowExW(exStyle, className.c_str(), windowName.c_str(),
                                     style, x, y, w, h, parent, menu_h,
                                     GetModuleHandleW(NULL), NULL);
        if (hwnd) {
            auto it = arm_wndprocs.find(className);
            if (it != arm_wndprocs.end()) {
                hwnd_wndproc_map[hwnd] = it->second;
                printf("[THUNK]   HWND=%p mapped to ARM WndProc=0x%08X\n",
                       hwnd, it->second);
            }

            if (is_toplevel) {
                if (!windowName.empty()) {
                    SetWindowTextW(hwnd, windowName.c_str());
                }
                HICON hIcon = LoadIconW(NULL, IDI_APPLICATION);
                SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
                SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
            }
        }
        regs[0] = (uint32_t)(uintptr_t)hwnd;
        return true;
    }

    if (func == "ShowWindow") {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        if (hw == NULL && regs[1] == 5) {
            regs[0] = 0;
            return true;
        }
        regs[0] = ShowWindow(hw, regs[1]);
        return true;
    }
    if (func == "UpdateWindow") {
        regs[0] = UpdateWindow((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "DestroyWindow") {
        regs[0] = DestroyWindow((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "SetWindowPos") {
        HWND after = (HWND)(intptr_t)(int32_t)regs[1];
        regs[0] = SetWindowPos((HWND)(intptr_t)(int32_t)regs[0], after, regs[2], regs[3],
                               ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1),
                               ReadStackArg(regs, mem, 2));
        return true;
    }
    if (func == "MoveWindow") {
        regs[0] = MoveWindow((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3],
                             ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1));
        return true;
    }

    /* Rect functions */
    if (func == "SetRect") {
        uint32_t r_addr = regs[0];
        mem.Write32(r_addr, regs[1]);
        mem.Write32(r_addr + 4, regs[2]);
        mem.Write32(r_addr + 8, regs[3]);
        mem.Write32(r_addr + 12, ReadStackArg(regs, mem, 0));
        regs[0] = 1;
        return true;
    }
    if (func == "CopyRect") {
        for (int i = 0; i < 4; i++)
            mem.Write32(regs[0] + i * 4, mem.Read32(regs[1] + i * 4));
        regs[0] = 1;
        return true;
    }
    if (func == "SetRectEmpty") {
        for (int i = 0; i < 4; i++) mem.Write32(regs[0] + i * 4, 0);
        regs[0] = 1;
        return true;
    }
    if (func == "InflateRect") {
        int32_t l = (int32_t)mem.Read32(regs[0]);
        int32_t t = (int32_t)mem.Read32(regs[0] + 4);
        int32_t r_v = (int32_t)mem.Read32(regs[0] + 8);
        int32_t b = (int32_t)mem.Read32(regs[0] + 12);
        int32_t dx = (int32_t)regs[1], dy = (int32_t)regs[2];
        mem.Write32(regs[0], l - dx);
        mem.Write32(regs[0] + 4, t - dy);
        mem.Write32(regs[0] + 8, r_v + dx);
        mem.Write32(regs[0] + 12, b + dy);
        regs[0] = 1;
        return true;
    }
    if (func == "OffsetRect") {
        RECT rc;
        rc.left = (int32_t)mem.Read32(regs[0]);
        rc.top = (int32_t)mem.Read32(regs[0]+4);
        rc.right = (int32_t)mem.Read32(regs[0]+8);
        rc.bottom = (int32_t)mem.Read32(regs[0]+12);
        OffsetRect(&rc, (int)regs[1], (int)regs[2]);
        mem.Write32(regs[0], rc.left);
        mem.Write32(regs[0]+4, rc.top);
        mem.Write32(regs[0]+8, rc.right);
        mem.Write32(regs[0]+12, rc.bottom);
        regs[0] = 1;
        return true;
    }
    if (func == "IntersectRect") {
        RECT a, b, out;
        a.left = mem.Read32(regs[1]); a.top = mem.Read32(regs[1]+4);
        a.right = mem.Read32(regs[1]+8); a.bottom = mem.Read32(regs[1]+12);
        b.left = mem.Read32(regs[2]); b.top = mem.Read32(regs[2]+4);
        b.right = mem.Read32(regs[2]+8); b.bottom = mem.Read32(regs[2]+12);
        BOOL ret = IntersectRect(&out, &a, &b);
        mem.Write32(regs[0], out.left); mem.Write32(regs[0]+4, out.top);
        mem.Write32(regs[0]+8, out.right); mem.Write32(regs[0]+12, out.bottom);
        regs[0] = ret;
        return true;
    }
    if (func == "UnionRect") {
        RECT a, b, out;
        a.left = mem.Read32(regs[1]); a.top = mem.Read32(regs[1]+4);
        a.right = mem.Read32(regs[1]+8); a.bottom = mem.Read32(regs[1]+12);
        b.left = mem.Read32(regs[2]); b.top = mem.Read32(regs[2]+4);
        b.right = mem.Read32(regs[2]+8); b.bottom = mem.Read32(regs[2]+12);
        BOOL ret = UnionRect(&out, &a, &b);
        mem.Write32(regs[0], out.left); mem.Write32(regs[0]+4, out.top);
        mem.Write32(regs[0]+8, out.right); mem.Write32(regs[0]+12, out.bottom);
        regs[0] = ret;
        return true;
    }
    if (func == "PtInRect") {
        RECT rc;
        rc.left = mem.Read32(regs[0]); rc.top = mem.Read32(regs[0]+4);
        rc.right = mem.Read32(regs[0]+8); rc.bottom = mem.Read32(regs[0]+12);
        POINT pt = { (LONG)regs[1], (LONG)regs[2] };
        regs[0] = PtInRect(&rc, pt);
        return true;
    }
    if (func == "IsRectEmpty") {
        int32_t l = mem.Read32(regs[0]), t = mem.Read32(regs[0]+4);
        int32_t r_v = mem.Read32(regs[0]+8), b = mem.Read32(regs[0]+12);
        regs[0] = (r_v <= l || b <= t) ? 1 : 0;
        return true;
    }
    if (func == "EqualRect") {
        bool eq = true;
        for (int i = 0; i < 4; i++)
            if (mem.Read32(regs[0] + i*4) != mem.Read32(regs[1] + i*4)) eq = false;
        regs[0] = eq ? 1 : 0;
        return true;
    }
    if (func == "SubtractRect") {
        regs[0] = 0; /* Stub */
        return true;
    }

    /* Window query */
    if (func == "GetWindowRect") {
        RECT rc;
        BOOL ret = GetWindowRect((HWND)(intptr_t)(int32_t)regs[0], &rc);
        mem.Write32(regs[1], rc.left); mem.Write32(regs[1]+4, rc.top);
        mem.Write32(regs[1]+8, rc.right); mem.Write32(regs[1]+12, rc.bottom);
        regs[0] = ret;
        return true;
    }
    if (func == "GetClientRect") {
        RECT rc;
        BOOL ret = GetClientRect((HWND)(intptr_t)(int32_t)regs[0], &rc);
        mem.Write32(regs[1], rc.left); mem.Write32(regs[1]+4, rc.top);
        mem.Write32(regs[1]+8, rc.right); mem.Write32(regs[1]+12, rc.bottom);
        regs[0] = ret;
        return true;
    }
    if (func == "InvalidateRect") {
        RECT* prc = NULL;
        RECT rc;
        if (regs[1]) {
            rc.left = mem.Read32(regs[1]); rc.top = mem.Read32(regs[1]+4);
            rc.right = mem.Read32(regs[1]+8); rc.bottom = mem.Read32(regs[1]+12);
            prc = &rc;
        }
        regs[0] = InvalidateRect((HWND)(intptr_t)(int32_t)regs[0], prc, regs[2]);
        return true;
    }
    if (func == "ValidateRect") {
        regs[0] = ValidateRect((HWND)(intptr_t)(int32_t)regs[0], NULL);
        return true;
    }
    if (func == "GetUpdateRect") {
        RECT rc;
        BOOL ret = GetUpdateRect((HWND)(intptr_t)(int32_t)regs[0], &rc, regs[2]);
        if (regs[1]) {
            mem.Write32(regs[1], rc.left); mem.Write32(regs[1]+4, rc.top);
            mem.Write32(regs[1]+8, rc.right); mem.Write32(regs[1]+12, rc.bottom);
        }
        regs[0] = ret;
        return true;
    }
    if (func == "GetParent") {
        regs[0] = (uint32_t)(uintptr_t)GetParent((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "IsWindow") {
        regs[0] = IsWindow((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "IsWindowVisible") {
        regs[0] = IsWindowVisible((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "GetDlgItem") {
        regs[0] = (uint32_t)(uintptr_t)GetDlgItem((HWND)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "SetDlgItemTextW") {
        std::wstring text = ReadWStringFromEmu(mem, regs[2]);
        regs[0] = SetDlgItemTextW((HWND)(intptr_t)(int32_t)regs[0], regs[1], text.c_str());
        return true;
    }
    if (func == "GetDlgItemTextW") {
        wchar_t buf[1024] = {};
        uint32_t maxlen = regs[3];
        if (maxlen > 1024) maxlen = 1024;
        int ret = GetDlgItemTextW((HWND)(intptr_t)(int32_t)regs[0], regs[1], buf, maxlen);
        uint32_t dst = regs[2];
        for (int i = 0; i <= ret; i++) mem.Write16(dst + i * 2, buf[i]);
        regs[0] = ret;
        return true;
    }
    if (func == "SendDlgItemMessageW") {
        regs[0] = (uint32_t)SendDlgItemMessageW((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs, mem, 0));
        return true;
    }
    if (func == "CheckRadioButton") {
        regs[0] = CheckRadioButton((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]);
        return true;
    }
    if (func == "DefDlgProcW") {
        regs[0] = (uint32_t)DefDlgProcW((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]);
        return true;
    }
    if (func == "GetDlgCtrlID") {
        regs[0] = GetDlgCtrlID((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "GetNextDlgTabItem") {
        regs[0] = (uint32_t)(uintptr_t)GetNextDlgTabItem(
            (HWND)(intptr_t)(int32_t)regs[0], (HWND)(intptr_t)(int32_t)regs[1], regs[2]);
        return true;
    }
    if (func == "EnableWindow") {
        regs[0] = EnableWindow((HWND)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "IsWindowEnabled") {
        regs[0] = IsWindowEnabled((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "SetWindowTextW") {
        std::wstring text = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = SetWindowTextW((HWND)(intptr_t)(int32_t)regs[0], text.c_str());
        return true;
    }
    if (func == "GetWindowLongW") {
        regs[0] = GetWindowLongW((HWND)(intptr_t)(int32_t)regs[0], (int)regs[1]);
        return true;
    }
    if (func == "SetWindowLongW") {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        int nIndex = (int)regs[1];
        LONG newVal = (LONG)regs[2];
        if (nIndex == GWL_EXSTYLE) {
            newVal &= 0x0FFFFFFF;
        }
        regs[0] = SetWindowLongW(hw, nIndex, newVal);
        return true;
    }
    if (func == "GetDesktopWindow") {
        regs[0] = (uint32_t)(uintptr_t)GetDesktopWindow();
        return true;
    }
    if (func == "GetForegroundWindow") {
        regs[0] = (uint32_t)(uintptr_t)GetForegroundWindow();
        return true;
    }
    if (func == "FindWindowW") {
        std::wstring class_name = ReadWStringFromEmu(mem, regs[0]);
        std::wstring window_name = ReadWStringFromEmu(mem, regs[1]);
        HWND h = FindWindowW(
            regs[0] ? class_name.c_str() : NULL,
            regs[1] ? window_name.c_str() : NULL);
        regs[0] = (uint32_t)(uintptr_t)h;
        printf("[THUNK] FindWindowW('%ls', '%ls') -> 0x%08X\n",
               class_name.c_str(), window_name.c_str(), regs[0]);
        return true;
    }
    if (func == "SetForegroundWindow") {
        regs[0] = SetForegroundWindow((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "SetActiveWindow") {
        regs[0] = (uint32_t)(uintptr_t)SetActiveWindow((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "GetActiveWindow") {
        regs[0] = (uint32_t)(uintptr_t)GetActiveWindow();
        return true;
    }
    if (func == "SetFocus") {
        regs[0] = (uint32_t)(uintptr_t)SetFocus((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "GetFocus") {
        regs[0] = (uint32_t)(uintptr_t)GetFocus();
        return true;
    }
    if (func == "SetCapture") {
        regs[0] = (uint32_t)(uintptr_t)SetCapture((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "ReleaseCapture") {
        regs[0] = ReleaseCapture();
        return true;
    }
    if (func == "SetCursor") {
        regs[0] = (uint32_t)(uintptr_t)SetCursor((HCURSOR)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "LoadCursorW") {
        regs[0] = (uint32_t)(uintptr_t)LoadCursorW((HINSTANCE)(intptr_t)(int32_t)regs[0],
                                                     MAKEINTRESOURCEW(regs[1]));
        return true;
    }
    if (func == "LoadIconW") {
        regs[0] = (uint32_t)(uintptr_t)LoadIconW((HINSTANCE)(intptr_t)(int32_t)regs[0],
                                                   MAKEINTRESOURCEW(regs[1]));
        return true;
    }
    if (func == "BringWindowToTop") {
        regs[0] = BringWindowToTop((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "GetWindow") {
        regs[0] = (uint32_t)(uintptr_t)GetWindow((HWND)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "MapWindowPoints") {
        regs[0] = 0; /* Stub */
        return true;
    }
    if (func == "SetParent") {
        regs[0] = (uint32_t)(uintptr_t)SetParent((HWND)(intptr_t)(int32_t)regs[0], (HWND)(intptr_t)(int32_t)regs[1]);
        return true;
    }

    /* Message loop */
    if (func == "GetMessageW") {
        MSG msg;
        BOOL ret = GetMessageW(&msg, (HWND)(intptr_t)(int32_t)regs[1], regs[2], regs[3]);
        uint32_t msg_addr = regs[0];
        mem.Write32(msg_addr + 0, (uint32_t)(uintptr_t)msg.hwnd);
        mem.Write32(msg_addr + 4, msg.message);
        mem.Write32(msg_addr + 8, (uint32_t)msg.wParam);
        mem.Write32(msg_addr + 12, (uint32_t)msg.lParam);
        mem.Write32(msg_addr + 16, msg.time);
        mem.Write32(msg_addr + 20, msg.pt.x);
        mem.Write32(msg_addr + 24, msg.pt.y);
        regs[0] = ret;
        return true;
    }
    if (func == "PeekMessageW") {
        MSG msg;
        BOOL ret = PeekMessageW(&msg, (HWND)(intptr_t)(int32_t)regs[1], regs[2], regs[3],
                                ReadStackArg(regs, mem, 0));
        uint32_t msg_addr = regs[0];
        mem.Write32(msg_addr + 0, (uint32_t)(uintptr_t)msg.hwnd);
        mem.Write32(msg_addr + 4, msg.message);
        mem.Write32(msg_addr + 8, (uint32_t)msg.wParam);
        mem.Write32(msg_addr + 12, (uint32_t)msg.lParam);
        mem.Write32(msg_addr + 16, msg.time);
        mem.Write32(msg_addr + 20, msg.pt.x);
        mem.Write32(msg_addr + 24, msg.pt.y);
        regs[0] = ret;
        return true;
    }
    if (func == "TranslateMessage") {
        MSG msg;
        msg.hwnd = (HWND)(intptr_t)(int32_t)mem.Read32(regs[0]);
        msg.message = mem.Read32(regs[0] + 4);
        msg.wParam = mem.Read32(regs[0] + 8);
        msg.lParam = mem.Read32(regs[0] + 12);
        msg.time = mem.Read32(regs[0] + 16);
        msg.pt.x = mem.Read32(regs[0] + 20);
        msg.pt.y = mem.Read32(regs[0] + 24);
        regs[0] = TranslateMessage(&msg);
        return true;
    }
    if (func == "MsgWaitForMultipleObjectsEx") {
        DWORD dwMilliseconds = regs[2];
        DWORD dwWakeMask = regs[3];
        DWORD dwFlags = ReadStackArg(regs, mem, 0);
        regs[0] = MsgWaitForMultipleObjectsEx(0, NULL, dwMilliseconds, dwWakeMask, dwFlags);
        return true;
    }
    if (func == "SendNotifyMessageW") {
        regs[0] = SendNotifyMessageW((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]);
        return true;
    }
    if (func == "DispatchMessageW") {
        uint32_t raw_hwnd = mem.Read32(regs[0]);
        HWND hwnd = (HWND)(intptr_t)(int32_t)raw_hwnd;
        uint32_t message = mem.Read32(regs[0] + 4);
        uint32_t wParam = mem.Read32(regs[0] + 8);
        uint32_t lParam = mem.Read32(regs[0] + 12);

        if (message == WM_TIMER && callback_executor) {
            UINT_PTR timerID = wParam;
            auto tc_it = arm_timer_callbacks.find(timerID);
            if (tc_it != arm_timer_callbacks.end()) {
                uint32_t args[4] = { raw_hwnd, WM_TIMER, (uint32_t)timerID, GetTickCount() };
                callback_executor(tc_it->second, args, 4);
                regs[0] = 0;
                return true;
            }
        }

        auto it = hwnd_wndproc_map.find(hwnd);
        if (it != hwnd_wndproc_map.end() && callback_executor) {
            uint32_t args[4] = { (uint32_t)(uintptr_t)hwnd, message, wParam, lParam };
            regs[0] = callback_executor(it->second, args, 4);
        } else {
            MSG msg = {};
            msg.hwnd = hwnd;
            msg.message = message;
            msg.wParam = wParam;
            msg.lParam = lParam;
            msg.time = mem.Read32(regs[0] + 16);
            msg.pt.x = mem.Read32(regs[0] + 20);
            msg.pt.y = mem.Read32(regs[0] + 24);
            regs[0] = (uint32_t)DispatchMessageW(&msg);
        }
        return true;
    }
    if (func == "PostMessageW") {
        regs[0] = PostMessageW((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]);
        return true;
    }
    if (func == "SendMessageW") {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        UINT umsg = regs[1];
        WPARAM wp = regs[2];
        LPARAM lp = regs[3];
        if (umsg == WM_SETTEXT && lp != 0) {
            std::wstring text = ReadWStringFromEmu(mem, (uint32_t)lp);
            regs[0] = (uint32_t)SendMessageW(hw, umsg, wp, (LPARAM)text.c_str());
        } else if (umsg == WM_GETTEXT && lp != 0) {
            int maxlen = (int)wp;
            std::vector<wchar_t> buf(maxlen + 1, 0);
            LRESULT len = SendMessageW(hw, umsg, wp, (LPARAM)buf.data());
            for (int i = 0; i <= (int)len && i < maxlen; i++)
                mem.Write16((uint32_t)lp + i * 2, buf[i]);
            mem.Write16((uint32_t)lp + (int)len * 2, 0);
            regs[0] = (uint32_t)len;
        } else {
            regs[0] = (uint32_t)SendMessageW(hw, umsg, wp, lp);
        }
        return true;
    }
    if (func == "PostQuitMessage") {
        PostQuitMessage(regs[0]);
        return true;
    }
    if (func == "IsDialogMessageW") {
        regs[0] = 0;
        return true;
    }
    if (func == "DefWindowProcW") {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        UINT umsg = regs[1];
        WPARAM wp = regs[2];
        LPARAM lp = regs[3];
        if ((umsg == WM_CREATE || umsg == WM_NCCREATE) && lp != 0) {
            regs[0] = (umsg == WM_NCCREATE) ? 1 : 0;
        } else {
            regs[0] = (uint32_t)DefWindowProcW(hw, umsg, wp, lp);
        }
        return true;
    }
    if (func == "MessageBoxW") {
        std::wstring text = ReadWStringFromEmu(mem, regs[1]);
        std::wstring title = ReadWStringFromEmu(mem, regs[2]);
        regs[0] = MessageBoxW((HWND)(intptr_t)(int32_t)regs[0], text.c_str(), title.c_str(), regs[3]);
        return true;
    }
    if (func == "MessageBeep") {
        MessageBeep(regs[0]);
        regs[0] = 1;
        return true;
    }

    /* Misc user */
    if (func == "SetTimer") {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        UINT_PTR nIDEvent = regs[1];
        UINT uElapse = regs[2];
        uint32_t arm_timerproc = regs[3];
        if (arm_timerproc != 0) {
            arm_timer_callbacks[nIDEvent] = arm_timerproc;
        }
        regs[0] = (uint32_t)(uintptr_t)SetTimer(hw, nIDEvent, uElapse, NULL);
        return true;
    }
    if (func == "KillTimer") {
        arm_timer_callbacks.erase(regs[1]);
        regs[0] = KillTimer((HWND)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "GetKeyState") {
        regs[0] = (uint32_t)GetKeyState(regs[0]);
        return true;
    }
    if (func == "GetAsyncKeyState") {
        regs[0] = (uint32_t)GetAsyncKeyState(regs[0]);
        return true;
    }
    if (func == "AdjustWindowRectEx") {
        RECT rc;
        rc.left = mem.Read32(regs[0]); rc.top = mem.Read32(regs[0]+4);
        rc.right = mem.Read32(regs[0]+8); rc.bottom = mem.Read32(regs[0]+12);
        BOOL ret = AdjustWindowRectEx(&rc, regs[1], regs[2], regs[3]);
        mem.Write32(regs[0], rc.left); mem.Write32(regs[0]+4, rc.top);
        mem.Write32(regs[0]+8, rc.right); mem.Write32(regs[0]+12, rc.bottom);
        regs[0] = ret;
        return true;
    }
    if (func == "GetDoubleClickTime") {
        regs[0] = GetDoubleClickTime();
        return true;
    }
    if (func == "GetCursorPos") {
        POINT pt;
        GetCursorPos(&pt);
        mem.Write32(regs[0], pt.x);
        mem.Write32(regs[0]+4, pt.y);
        regs[0] = 1;
        return true;
    }
    if (func == "ScreenToClient") {
        POINT pt;
        pt.x = mem.Read32(regs[1]);
        pt.y = mem.Read32(regs[1]+4);
        BOOL ret = ScreenToClient((HWND)(intptr_t)(int32_t)regs[0], &pt);
        mem.Write32(regs[1], pt.x);
        mem.Write32(regs[1]+4, pt.y);
        regs[0] = ret;
        return true;
    }
    if (func == "ClientToScreen") {
        POINT pt;
        pt.x = mem.Read32(regs[1]);
        pt.y = mem.Read32(regs[1]+4);
        BOOL ret = ClientToScreen((HWND)(intptr_t)(int32_t)regs[0], &pt);
        mem.Write32(regs[1], pt.x);
        mem.Write32(regs[1]+4, pt.y);
        regs[0] = ret;
        return true;
    }
    if (func == "GetMessagePos") {
        regs[0] = GetMessagePos();
        return true;
    }
    if (func == "WindowFromPoint") {
        POINT pt = { (LONG)regs[0], (LONG)regs[1] };
        regs[0] = (uint32_t)(uintptr_t)WindowFromPoint(pt);
        return true;
    }
    if (func == "RegisterWindowMessageW") {
        std::wstring msg_name = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = RegisterWindowMessageW(msg_name.c_str());
        return true;
    }
    if (func == "GetWindowTextW" || func == "GetWindowTextLengthW") {
        if (func == "GetWindowTextLengthW") {
            regs[0] = GetWindowTextLengthW((HWND)(intptr_t)(int32_t)regs[0]);
        } else {
            wchar_t buf[1024] = {};
            uint32_t maxlen = regs[2];
            if (maxlen > 1024) maxlen = 1024;
            int ret = GetWindowTextW((HWND)(intptr_t)(int32_t)regs[0], buf, maxlen);
            uint32_t dst = regs[1];
            for (int i = 0; i <= ret; i++) mem.Write16(dst + i * 2, buf[i]);
            regs[0] = ret;
        }
        return true;
    }
    if (func == "GetClassInfoW" || func == "UnregisterClassW") {
        regs[0] = 0; /* Stub */
        return true;
    }
    if (func == "CallWindowProcW") {
        /* Stub - just call DefWindowProcW */
        regs[0] = (uint32_t)DefWindowProcW((HWND)(intptr_t)(int32_t)regs[1], regs[2], regs[3],
                                            ReadStackArg(regs, mem, 0));
        return true;
    }
    if (func == "ScrollWindowEx") {
        regs[0] = 0; /* Stub */
        return true;
    }
    if (func == "SetScrollInfo" || func == "SetScrollPos" || func == "SetScrollRange" || func == "GetScrollInfo") {
        regs[0] = 0; /* Stub */
        return true;
    }
    if (func == "EnumWindows" || func == "GetWindowThreadProcessId") {
        regs[0] = 0; /* Stub */
        return true;
    }
    if (func == "TranslateAcceleratorW" || func == "LoadAcceleratorsW") {
        regs[0] = 0; /* Stub */
        return true;
    }

    /* Menus */
    if (func == "CreateMenu") {
        regs[0] = (uint32_t)(uintptr_t)CreateMenu();
        return true;
    }
    if (func == "CreatePopupMenu") {
        regs[0] = (uint32_t)(uintptr_t)CreatePopupMenu();
        return true;
    }
    if (func == "DestroyMenu") {
        regs[0] = DestroyMenu((HMENU)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "GetSubMenu") {
        regs[0] = (uint32_t)(uintptr_t)GetSubMenu((HMENU)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "AppendMenuW") {
        std::wstring text = ReadWStringFromEmu(mem, regs[3]);
        regs[0] = AppendMenuW((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2],
                              (regs[1] & MF_STRING) ? text.c_str() : (LPCWSTR)(uintptr_t)regs[3]);
        return true;
    }
    if (func == "EnableMenuItem") {
        regs[0] = EnableMenuItem((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2]);
        return true;
    }
    if (func == "CheckMenuItem") {
        regs[0] = CheckMenuItem((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2]);
        return true;
    }
    if (func == "CheckMenuRadioItem") {
        regs[0] = CheckMenuRadioItem((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs, mem, 0));
        return true;
    }
    if (func == "DrawMenuBar") {
        regs[0] = DrawMenuBar((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "LoadMenuW") {
        regs[0] = (uint32_t)(uintptr_t)LoadMenuW((HINSTANCE)(intptr_t)(int32_t)regs[0], MAKEINTRESOURCEW(regs[1]));
        return true;
    }
    if (func == "TrackPopupMenuEx") {
        regs[0] = TrackPopupMenuEx((HMENU)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3],
                                    (HWND)(intptr_t)(int32_t)ReadStackArg(regs, mem, 0), NULL);
        return true;
    }

    /* Dialogs */
    if (func == "CreateDialogIndirectParamW") {
        uint32_t lpTemplate = regs[1];
        uint32_t hwndParent = regs[2];
        uint32_t arm_dlgProc = regs[3];
        LPARAM initParam = (LPARAM)ReadStackArg(regs, mem, 0);
        HWND parent = (HWND)(intptr_t)(int32_t)hwndParent;

        auto tmpl = CopyDlgTemplate(mem, lpTemplate);
        HWND dlg = CreateDialogIndirectParamW(
            GetModuleHandleW(NULL),
            (LPCDLGTEMPLATEW)tmpl.data(),
            parent,
            EmuDlgProc,
            initParam);

        if (dlg && arm_dlgProc) {
            hwnd_dlgproc_map[dlg] = arm_dlgProc;
        }
        regs[0] = (uint32_t)(uintptr_t)dlg;
        return true;
    }
    if (func == "DialogBoxIndirectParamW") {
        uint32_t lpTemplate = regs[1];
        uint32_t hwndParent = regs[2];
        uint32_t arm_dlgProc = regs[3];
        LPARAM initParam = (LPARAM)ReadStackArg(regs, mem, 0);
        HWND parent = (HWND)(intptr_t)(int32_t)hwndParent;

        auto tmpl = CopyDlgTemplate(mem, lpTemplate);
        modal_dlg_ended = false;
        modal_dlg_result = 0;
        HWND dlg = CreateDialogIndirectParamW(
            GetModuleHandleW(NULL),
            (LPCDLGTEMPLATEW)tmpl.data(),
            parent,
            EmuDlgProc,
            initParam);

        if (dlg && arm_dlgProc) {
            hwnd_dlgproc_map[dlg] = arm_dlgProc;
            uint32_t args[4] = { (uint32_t)(uintptr_t)dlg, WM_INITDIALOG, 0, (uint32_t)initParam };
            callback_executor(arm_dlgProc, args, 4);
        }

        if (dlg) {
            ShowWindow(dlg, SW_SHOW);
            if (parent) EnableWindow(parent, FALSE);

            MSG msg;
            while (!modal_dlg_ended && GetMessageW(&msg, NULL, 0, 0)) {
                if (!IsDialogMessageW(dlg, &msg)) {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }

            if (parent) EnableWindow(parent, TRUE);
            DestroyWindow(dlg);
            hwnd_dlgproc_map.erase(dlg);
            if (parent) SetForegroundWindow(parent);
        }

        regs[0] = (uint32_t)modal_dlg_result;
        return true;
    }
    if (func == "EndDialog") {
        HWND dlg = (HWND)(intptr_t)(int32_t)regs[0];
        modal_dlg_result = (INT_PTR)(int32_t)regs[1];
        modal_dlg_ended = true;
        ShowWindow(dlg, SW_HIDE);
        regs[0] = 1;
        return true;
    }

    return false;
}
