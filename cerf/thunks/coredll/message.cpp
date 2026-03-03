/* Message thunks: GetMessage, Peek, Post, Send, Dispatch, Translate */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>
#include <commctrl.h>

void Win32Thunks::RegisterMessageHandlers() {
    Thunk("GetMessageW", 861, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        MSG msg;
        BOOL ret = GetMessageW(&msg, (HWND)(intptr_t)(int32_t)regs[1], regs[2], regs[3]);
        uint32_t a = regs[0];
        mem.Write32(a+0, (uint32_t)(uintptr_t)msg.hwnd); mem.Write32(a+4, msg.message);
        mem.Write32(a+8, (uint32_t)msg.wParam); mem.Write32(a+12, (uint32_t)msg.lParam);
        mem.Write32(a+16, msg.time); mem.Write32(a+20, msg.pt.x); mem.Write32(a+24, msg.pt.y);
        regs[0] = ret;
        return true;
    });
    Thunk("PeekMessageW", 864, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        MSG msg;
        BOOL ret = PeekMessageW(&msg, (HWND)(intptr_t)(int32_t)regs[1], regs[2], regs[3], ReadStackArg(regs, mem, 0));
        uint32_t a = regs[0];
        mem.Write32(a+0, (uint32_t)(uintptr_t)msg.hwnd); mem.Write32(a+4, msg.message);
        mem.Write32(a+8, (uint32_t)msg.wParam); mem.Write32(a+12, (uint32_t)msg.lParam);
        mem.Write32(a+16, msg.time); mem.Write32(a+20, msg.pt.x); mem.Write32(a+24, msg.pt.y);
        regs[0] = ret;
        return true;
    });
    Thunk("TranslateMessage", 870, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        MSG msg;
        msg.hwnd = (HWND)(intptr_t)(int32_t)mem.Read32(regs[0]);
        msg.message = mem.Read32(regs[0]+4); msg.wParam = mem.Read32(regs[0]+8);
        msg.lParam = mem.Read32(regs[0]+12); msg.time = mem.Read32(regs[0]+16);
        msg.pt.x = mem.Read32(regs[0]+20); msg.pt.y = mem.Read32(regs[0]+24);
        regs[0] = TranslateMessage(&msg);
        return true;
    });
    Thunk("DispatchMessageW", 859, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t raw_hwnd = mem.Read32(regs[0]);
        HWND hwnd = (HWND)(intptr_t)(int32_t)raw_hwnd;
        uint32_t message = mem.Read32(regs[0]+4), wParam = mem.Read32(regs[0]+8), lParam = mem.Read32(regs[0]+12);
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
            MSG msg = {}; msg.hwnd = hwnd; msg.message = message; msg.wParam = wParam; msg.lParam = lParam;
            msg.time = mem.Read32(regs[0]+16); msg.pt.x = mem.Read32(regs[0]+20); msg.pt.y = mem.Read32(regs[0]+24);
            regs[0] = (uint32_t)DispatchMessageW(&msg);
        }
        return true;
    });
    Thunk("PostMessageW", 865, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = PostMessageW((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]);
        return true;
    });
    Thunk("SendMessageW", 868, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0]; UINT umsg = regs[1]; WPARAM wp = regs[2]; LPARAM lp = regs[3];
        /* WM_SETFONT: wParam is an HFONT handle — must sign-extend for 64-bit */
        if (umsg == WM_SETFONT) {
            wp = (WPARAM)(intptr_t)(int32_t)regs[2];
            LOG(THUNK, "[THUNK] SendMessage WM_SETFONT hwnd=%p hFont=0x%08X -> %p\n",
                hw, regs[2], (HFONT)wp);
        }
        /* TB_ADDBITMAP: marshal TBADDBITMAP from ARM memory.
           ARM struct: {HINSTANCE(4), UINT_PTR nID(4)} = 8 bytes
           x64 struct: {HINSTANCE(8), UINT_PTR nID(8)} = 16 bytes */
        if (umsg == TB_ADDBITMAP && lp != 0 && mem.IsValid((uint32_t)lp)) {
            uint32_t arm_hInst = mem.Read32((uint32_t)lp);
            uint32_t arm_nID = mem.Read32((uint32_t)lp + 4);
            /* WinCE bitmap IDs 140 (close) and 142 (help) don't exist on desktop.
               Skip them — the button will be blank but functional. */
            if (arm_hInst == 0xFFFFFFFF && (arm_nID == 140 || arm_nID == 142)) {
                regs[0] = 0;
                LOG(THUNK, "[THUNK] TB_ADDBITMAP WinCE bitmap %u -> skipped (no desktop equivalent)\n", arm_nID);
                return true;
            }
            TBADDBITMAP tbab;
            tbab.hInst = (HINSTANCE)(intptr_t)(int32_t)arm_hInst;
            tbab.nID = arm_nID;
            regs[0] = (uint32_t)SendMessageW(hw, TB_ADDBITMAP, wp, (LPARAM)&tbab);
            return true;
        }
        /* Marshal ARM pointers to native.
           Messages that pass strings in lParam need conversion from
           emulated ARM addresses to native pointers. */
        bool lp_is_string = (lp != 0) && (
            umsg == WM_SETTEXT ||
            umsg == CB_ADDSTRING || umsg == CB_FINDSTRING ||
            umsg == CB_FINDSTRINGEXACT || umsg == CB_INSERTSTRING ||
            umsg == CB_SELECTSTRING ||
            umsg == LB_ADDSTRING || umsg == LB_FINDSTRING ||
            umsg == LB_FINDSTRINGEXACT || umsg == LB_INSERTSTRING ||
            umsg == LB_SELECTSTRING);
        if (lp_is_string) {
            std::wstring text = ReadWStringFromEmu(mem, (uint32_t)lp);
            regs[0] = (uint32_t)SendMessageW(hw, umsg, wp, (LPARAM)text.c_str());
        } else if (umsg == WM_GETTEXT && lp != 0) {
            int maxlen = (int)wp;
            std::vector<wchar_t> buf(maxlen + 1, 0);
            LRESULT len = SendMessageW(hw, umsg, wp, (LPARAM)buf.data());
            for (int i = 0; i <= (int)len && i < maxlen; i++) mem.Write16((uint32_t)lp + i * 2, buf[i]);
            mem.Write16((uint32_t)lp + (int)len * 2, 0);
            regs[0] = (uint32_t)len;
        } else if ((umsg == CB_GETLBTEXT || umsg == LB_GETTEXT) && lp != 0) {
            wchar_t buf[256] = {};
            LRESULT len = SendMessageW(hw, umsg, wp, (LPARAM)buf);
            if (len != CB_ERR) {
                for (int i = 0; i <= (int)len; i++) mem.Write16((uint32_t)lp + i * 2, buf[i]);
            }
            regs[0] = (uint32_t)len;
        } else {
            regs[0] = (uint32_t)SendMessageW(hw, umsg, wp, lp);
        }
        return true;
    });
    Thunk("PostQuitMessage", 866, [](uint32_t* regs, EmulatedMemory&) -> bool {
        PostQuitMessage(regs[0]); return true;
    });
    Thunk("DefWindowProcW", 264, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0]; UINT umsg = regs[1];
        if ((umsg == WM_CREATE || umsg == WM_NCCREATE) && regs[3] != 0) {
            regs[0] = (umsg == WM_NCCREATE) ? 1 : 0;
        } else {
            regs[0] = (uint32_t)DefWindowProcW(hw, umsg, regs[2], regs[3]);
        }
        return true;
    });
    Thunk("MessageBoxW", 858, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring text = ReadWStringFromEmu(mem, regs[1]);
        std::wstring title = ReadWStringFromEmu(mem, regs[2]);
        LOG(THUNK, "[THUNK] MessageBoxW(hwnd=0x%08X, text='%ls', title='%ls', type=0x%X)\n",
            regs[0], text.c_str(), title.c_str(), regs[3]);
        regs[0] = MessageBoxW((HWND)(intptr_t)(int32_t)regs[0], text.c_str(), title.c_str(), regs[3]);
        return true;
    });
    Thunk("MessageBeep", 857, [](uint32_t* regs, EmulatedMemory&) -> bool {
        MessageBeep(regs[0]); regs[0] = 1; return true;
    });
    Thunk("MsgWaitForMultipleObjectsEx", 871, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = MsgWaitForMultipleObjectsEx(0, NULL, regs[2], regs[3], ReadStackArg(regs, mem, 0));
        return true;
    });
    Thunk("SendNotifyMessageW", 869, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SendNotifyMessageW((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]);
        return true;
    });
    Thunk("GetMessagePos", 862, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetMessagePos(); return true;
    });
    Thunk("TranslateAcceleratorW", 838, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
}
