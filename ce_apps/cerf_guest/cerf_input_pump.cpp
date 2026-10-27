#include <windows.h>

#include "cerf_coredll_proc.h"
#include "cerf_regs_map.h"
#include "cerf_debug_log.h"
#include "cerf_gwes_ready.h"
#include "cerf_input_pump.h"

#include "cerfcore/peripherals/cerf_virt/cerf_virt_addr_map.h"
#include "cerfcore/peripherals/cerf_virt/cerf_virt_keyboard_regs.h"
#include "cerfcore/peripherals/cerf_virt/cerf_virt_pointer_regs.h"

#define CERF_INPUT_POLL_MS    10u
#define CERF_INPUT_CE_PRIO    145

typedef VOID (WINAPI *PFN_mouse_event)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef VOID (WINAPI *PFN_keybd_event)(BYTE, BYTE, DWORD, DWORD);
typedef BOOL (WINAPI *PFN_CeSetThreadPriority)(HANDLE, int);

static void CerfInputBoost(void) {
    PFN_CeSetThreadPriority csp =
        (PFN_CeSetThreadPriority)CerfCoredllProc(L"CeSetThreadPriority");
    if (csp) csp(GetCurrentThread(), CERF_INPUT_CE_PRIO);
    else     SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
}

static void CerfSendButton(PFN_mouse_event me, ULONG btn, ULONG changed, ULONG bit, DWORD down, DWORD up) {
    if (changed & bit) me((btn & bit) ? down : up, 0, 0, 0, 0);
}

static DWORD WINAPI CerfInputPumpThread(LPVOID) {
    using namespace cerfcore::CerfVirt;
    PFN_mouse_event me = (PFN_mouse_event)CerfCoredllProc(L"mouse_event");
    PFN_keybd_event ke = (PFN_keybd_event)CerfCoredllProc(L"keybd_event");
    volatile ULONG* ptr = NULL;
    volatile ULONG* kb  = NULL;
    ULONG last_seq  = 0;
    ULONG last_btn  = 0;
    LONG  last_wheel = 0;
    ULONG consumed  = 0;

    CerfInputBoost();
    CERF_LOG_X("cerf_guest: inputpump mouse_event", (DWORD)me);
    CERF_LOG_X("cerf_guest: inputpump keybd_event", (DWORD)ke);

    if (me) {
        ptr = (volatile ULONG*)CerfMapRegsPage(g_CerfVirtBase + kPointerOffset, kPointerSize);
        if (!ptr) me = NULL;
    }
    if (ke) {
        kb = (volatile ULONG*)CerfMapRegsPage(g_CerfVirtBase + kKeyboardOffset, kKeyboardSize);
        if (!kb) ke = NULL;
    }
    if (!me && !ke) {
        CERF_LOG("cerf_guest: inputpump init FAILED");
        return 0;
    }

    if (!CerfWaitGwesApiSet()) {
        CERF_LOG_X("cerf_guest: inputpump SH_WMGR never registered - no input injection",
                   CerfShWmgrApiSet());
        return 0;
    }

    if (me) {
        last_seq   = ptr[kPtrAttach / 4];
        last_wheel = (LONG)ptr[kPtrWheelAccum / 4];
    }
    if (ke) consumed = kb[kKbWriteSeq / 4];

    for (;;) {
        if (me) {
            ULONG seq = ptr[kPtrSeq / 4];
            if (seq != last_seq) {
                DWORD nx    = ptr[kPtrX / 4];
                DWORD ny    = ptr[kPtrY / 4];
                ULONG btn   = ptr[kPtrButtons / 4];
                LONG  wheel = (LONG)ptr[kPtrWheelAccum / 4];
                ULONG changed;
                last_seq = seq;

                me(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE, nx, ny, 0, 0);

                changed = btn ^ last_btn;
                CerfSendButton(me, btn, changed, kPtrButtonLeft, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP);
                CerfSendButton(me, btn, changed, kPtrButtonRight, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP);
                CerfSendButton(me, btn, changed, kPtrButtonMiddle, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP);
                last_btn = btn;

                if (wheel != last_wheel) {
                    me(MOUSEEVENTF_WHEEL, 0, 0, (DWORD)(wheel - last_wheel), 0);
                    last_wheel = wheel;
                }
            }
        }

        if (ke) {
            ULONG wseq = kb[kKbWriteSeq / 4];
            while (consumed != wseq) {
                ULONG idx, entry;
                BYTE  vk;
                DWORD flags;
                if ((ULONG)(wseq - consumed) > kKbRingCount)
                    consumed = wseq - kKbRingCount;
                idx   = consumed % kKbRingCount;
                entry = kb[(kKbRingBase / 4) + idx];
                vk    = (BYTE)(entry & kKbEntryVkMask);
                flags = (entry & kKbEntryKeyUpBit) ? KEYEVENTF_KEYUP : 0u;
                ke(vk, 0, flags, 0);
                CERF_LOG_X("cerf_guest: inputpump key inject", entry);
                consumed++;
            }
        }

        Sleep(CERF_INPUT_POLL_MS);
    }
}

extern "C" void CerfStartInputPump(void) {
    static BOOL started = FALSE;
    HANDLE t;
    if (started) return;
    started = TRUE;
    t = CreateThread(NULL, 0, CerfInputPumpThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
}
