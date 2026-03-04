/* Message thunks: GetMessage, Peek, Post, Send, Dispatch, Translate */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>

void Win32Thunks::RegisterMessageHandlers() {
    Thunk("GetMessageW", 861, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        MSG msg;
        BOOL ret;
        while (true) {
            ret = GetMessageW(&msg, (HWND)(intptr_t)(int32_t)regs[1], regs[2], regs[3]);
            if (ret <= 0) break; /* WM_QUIT or error */
            /* WM_TIMER with native callbacks (non-ARM timers from toolbar, rebar, etc.):
               lParam contains a 64-bit native TIMERPROC address. If we pass this to ARM code,
               the address gets truncated to 32 bits and corrupted. Dispatch natively to call
               the correct callback, then get the next message. This prevents native timer
               messages from starving WM_PAINT and other low-priority messages. */
            if (msg.message == WM_TIMER && msg.hwnd == NULL && msg.lParam != 0) {
                UINT_PTR timerID = msg.wParam;
                if (arm_timer_callbacks.find(timerID) == arm_timer_callbacks.end()) {
                    DispatchMessageW(&msg);
                    continue;
                }
            }
            break;
        }
        LOG(API, "[API] GetMessageW -> msg=0x%04X hwnd=0x%p wP=0x%X lP=0x%X ret=%d\n",
            msg.message, msg.hwnd, (uint32_t)msg.wParam, (uint32_t)msg.lParam, ret);
        uint32_t a = regs[0];
        mem.Write32(a+0, (uint32_t)(uintptr_t)msg.hwnd); mem.Write32(a+4, msg.message);
        mem.Write32(a+8, (uint32_t)msg.wParam); mem.Write32(a+12, (uint32_t)msg.lParam);
        mem.Write32(a+16, msg.time); mem.Write32(a+20, msg.pt.x); mem.Write32(a+24, msg.pt.y);
        regs[0] = ret;
        return true;
    });
    Thunk("PeekMessageW", 864, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        MSG msg;
        UINT removeFlags = ReadStackArg(regs, mem, 0);
        BOOL ret;
        while (true) {
            ret = PeekMessageW(&msg, (HWND)(intptr_t)(int32_t)regs[1], regs[2], regs[3], removeFlags);
            if (!ret) break; /* No message */
            /* Same native-timer filter as GetMessageW */
            if (msg.message == WM_TIMER && msg.hwnd == NULL && msg.lParam != 0) {
                UINT_PTR timerID = msg.wParam;
                if (arm_timer_callbacks.find(timerID) == arm_timer_callbacks.end()) {
                    if (removeFlags & PM_REMOVE) DispatchMessageW(&msg);
                    continue;
                }
            }
            break;
        }
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
        LOG(API, "[API] DispatchMessageW: msg=0x%04X hwnd=0x%p wP=0x%X lP=0x%X\n",
            message, hwnd, wParam, lParam);
        if (message == WM_TIMER) {
            UINT_PTR timerID = wParam;
            auto tc_it = arm_timer_callbacks.find(timerID);
            if (tc_it != arm_timer_callbacks.end() && callback_executor) {
                uint32_t args[4] = { raw_hwnd, WM_TIMER, (uint32_t)timerID, GetTickCount() };
                callback_executor(tc_it->second, args, 4);
                regs[0] = 0;
                return true;
            }
            /* WM_TIMER with hwnd=NULL and not in arm_timer_callbacks:
               likely a native timer whose callback address was truncated.
               Don't try to dispatch it natively (would call corrupt address). */
            if (hwnd == NULL) { regs[0] = 0; return true; }
        }
        auto it = hwnd_wndproc_map.find(hwnd);
        if (it != hwnd_wndproc_map.end() && callback_executor) {
            if (message == WM_CHAR || message == WM_KEYDOWN || message == WM_LBUTTONDOWN) {
                wchar_t cls[64] = {};
                GetClassNameW(hwnd, cls, 64);
                LOG(API, "[API] Dispatch->ARM: msg=0x%04X hwnd=0x%p class='%ls' wP=0x%X lP=0x%X\n",
                    message, hwnd, cls, wParam, lParam);
            }
            uint32_t args[4] = { (uint32_t)(uintptr_t)hwnd, message, wParam, lParam };
            regs[0] = callback_executor(it->second, args, 4);
        } else {
            wchar_t cls[64] = {};
            if (hwnd) GetClassNameW(hwnd, cls, 64);
            LOG(API, "[API] DispatchMessageW NATIVE fallback: msg=0x%04X hwnd=0x%p class='%ls'\n",
                message, hwnd, cls);
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
        if (umsg == WM_COMMAND || umsg == WM_NOTIFY) {
            wchar_t cls[64] = {};
            if (hw) GetClassNameW(hw, cls, 64);
            LOG(API, "[API] SendMessageW(0x%p '%ls', msg=0x%X, wP=0x%X, lP=0x%X)\n",
                hw, cls, umsg, (uint32_t)wp, (uint32_t)lp);
        }
        /* WM_SETFONT: wParam is an HFONT handle — must sign-extend for 64-bit */
        if (umsg == WM_SETFONT) {
            wp = (WPARAM)(intptr_t)(int32_t)regs[2];
            LOG(API, "[API] SendMessage WM_SETFONT hwnd=%p hFont=0x%08X -> %p\n",
                hw, regs[2], (HFONT)wp);
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
            if (umsg == WM_NOTIFY) {
                LOG(API, "[API] SendMessageW WM_NOTIFY hwnd=%p wP=%d lP=0x%X -> ret=0x%X\n",
                    hw, (int)wp, (uint32_t)lp, regs[0]);
            }
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
        } else if (umsg == WM_SETTEXT && regs[3] != 0) {
            /* ARM lParam is an emulated memory pointer to a wchar string.
               Read it and pass a native pointer to DefWindowProcW. */
            std::wstring text = ReadWStringFromEmu(mem, regs[3]);
            regs[0] = (uint32_t)DefWindowProcW(hw, WM_SETTEXT, 0, (LPARAM)text.c_str());
        } else {
            regs[0] = (uint32_t)DefWindowProcW(hw, umsg, regs[2], regs[3]);
        }
        return true;
    });
    Thunk("MessageBoxW", 858, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring text = ReadWStringFromEmu(mem, regs[1]);
        std::wstring title = ReadWStringFromEmu(mem, regs[2]);
        LOG(API, "[API] MessageBoxW(hwnd=0x%08X, text='%ls', title='%ls', type=0x%X)\n",
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
