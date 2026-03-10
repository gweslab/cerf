/* Message thunks: GetMessage, Peek, Post, Send, Dispatch, Translate */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>

void Win32Thunks::RegisterMessageHandlers() {
    Thunk("GetMessageW", 861, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        MSG msg;
        BOOL ret;
        /* Real threading: each thread has its own message queue.
           Use blocking GetMessageW — no pseudo-thread hacks needed. */
        while (true) {
            ret = GetMessageW(&msg, (HWND)(intptr_t)(int32_t)regs[1], regs[2], regs[3]);
            if (ret <= 0) break; /* WM_QUIT or error */
            /* Filter native timer callbacks: if the timer ID isn't registered
               as an ARM callback, dispatch it natively and get next message. */
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
    Thunk("PostMessageW", 865, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        UINT msg = regs[1]; WPARAM wp = regs[2]; LPARAM lp = regs[3];
        LOG(API, "[API] PostMessageW(hwnd=0x%p, msg=0x%04X, wP=0x%X, lP=0x%X)\n",
            hw, msg, (uint32_t)wp, (uint32_t)lp);
        /* HWND_BROADCAST + WM_SETTINGCHANGE: use SendMessage for synchronous delivery.
           PostMessage during nested in-process execution may get lost because the
           modal message loop ends before the message is dispatched. */
        if (hw == HWND_BROADCAST && msg == WM_SETTINGCHANGE) {
            SendMessageW(HWND_BROADCAST, msg, wp, lp);
            regs[0] = 1;
        } else {
            regs[0] = PostMessageW(hw, msg, wp, lp);
        }
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
        /* TB_GETBUTTONINFOW: log the call and result for debugging menu bar issues */
        if (umsg == 0x43F) {
            wchar_t cls[64] = {};
            if (hw) GetClassNameW(hw, cls, 64);
            LOG(API, "[API] SendMessageW TB_GETBUTTONINFO(0x%p '%ls', id=%d, lP=0x%X)\n",
                hw, cls, (int)wp, (uint32_t)lp);
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
        }
        /* NOTE: No LVM_ marshaling needed — SysListView32 is ARM-controlled
           (registered by ARM commctrl.dll with EmuWndProc). ARM 32-bit pointers
           in lParam pass through native SendMessageW → EmuWndProc → ARM WndProc
           intact (zero-extended to 64-bit, then truncated back to 32-bit). */
        else {
            /* Log LVM_ messages to track ListView item insertion */
            if (umsg >= 0x1000 && umsg <= 0x10FF) {
                wchar_t cls[64] = {};
                GetClassNameW(hw, cls, 64);
                LOG(API, "[API] SendMessageW LVM_0x%04X hwnd=%p class='%ls' wP=0x%X lP=0x%X\n",
                    umsg, hw, cls, (uint32_t)wp, (uint32_t)lp);
            }
            regs[0] = (uint32_t)SendMessageW(hw, umsg, wp, lp);
            if (umsg >= 0x1000 && umsg <= 0x10FF) {
                LOG(API, "[API] SendMessageW LVM_0x%04X -> result=%d (0x%X)\n",
                    umsg, (int32_t)regs[0], regs[0]);
            }
            /* After LVM_SORTITEMS, query item positions for debugging. */
            if (umsg == 0x1030 /* LVM_SORTITEMS */) {
                int count = (int)SendMessageW(hw, 0x1004, 0, 0);
                RECT rc; GetWindowRect(hw, &rc);
                LOG(API, "[API] After LVM_SORTITEMS: hwnd=%p count=%d winRect=%ldx%ld\n",
                    hw, count, rc.right-rc.left, rc.bottom-rc.top);
                for (int i = 0; i < count && i < 5; i++) {
                    DWORD pos = (DWORD)SendMessageW(hw, 0x1010 /* LVM_GETITEMPOSITION */, i, 0);
                    /* LVM_GETITEMPOSITION with lParam=0 doesn't work. Need a POINT buffer.
                       Use alternative: check via ARM thunk. Skip for now. */
                }
                /* Post deferred arrange for after resize completes */
                PostMessageW(hw, 0x1016 /* LVM_ARRANGE */, 0, 0);
            }
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
        } else if ((umsg == WM_WINDOWPOSCHANGED || umsg == WM_WINDOWPOSCHANGING) && regs[3] != 0) {
            /* ARM lParam points to 32-bit WINDOWPOS in emulated memory.
               Marshal to native 64-bit WINDOWPOS for DefWindowProcW.
               ARM layout: hwnd(4) hwndInsertAfter(4) x(4) y(4) cx(4) cy(4) flags(4) */
            uint32_t a = regs[3];
            WINDOWPOS wp = {};
            wp.hwnd = (HWND)(intptr_t)(int32_t)mem.Read32(a + 0);
            wp.hwndInsertAfter = (HWND)(intptr_t)(int32_t)mem.Read32(a + 4);
            wp.x = (int)mem.Read32(a + 8);
            wp.y = (int)mem.Read32(a + 12);
            wp.cx = (int)mem.Read32(a + 16);
            wp.cy = (int)mem.Read32(a + 20);
            wp.flags = mem.Read32(a + 24);
            regs[0] = (uint32_t)DefWindowProcW(hw, umsg, regs[2], (LPARAM)&wp);
            /* Copy back for WM_WINDOWPOSCHANGING */
            if (umsg == WM_WINDOWPOSCHANGING) {
                mem.Write32(a + 8, wp.x);
                mem.Write32(a + 12, wp.y);
                mem.Write32(a + 16, wp.cx);
                mem.Write32(a + 20, wp.cy);
                mem.Write32(a + 24, wp.flags);
            }
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
