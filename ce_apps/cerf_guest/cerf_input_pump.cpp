#include <windows.h>

#include "cerf_regs_map.h"
#include "cerf_debug_log.h"
#include "cerf_gwes_ready.h"

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"

#define CERF_PTR_X            0x00u
#define CERF_PTR_Y            0x04u
#define CERF_PTR_BUTTONS      0x08u
#define CERF_PTR_WHEEL        0x0Cu
#define CERF_PTR_SEQ          0x10u

#define CERF_KB_WRITE_SEQ     0x00u
#define CERF_KB_RING_BASE     0x10u
#define CERF_KB_RING_COUNT    256u
#define CERF_KB_VK_MASK       0x00FFu
#define CERF_KB_KEYUP_BIT     0x0100u

#define CERF_INPUT_POLL_MS    10u
#define CERF_INPUT_CE_PRIO    145

typedef VOID (WINAPI *PFN_mouse_event)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef VOID (WINAPI *PFN_keybd_event)(BYTE, BYTE, DWORD, DWORD);
typedef BOOL (WINAPI *PFN_CeSetThreadPriority)(HANDLE, int);

static void CerfInputBoost(HMODULE core) {
    PFN_CeSetThreadPriority csp = core
        ? (PFN_CeSetThreadPriority)GetProcAddressW(core, L"CeSetThreadPriority") : NULL;
    if (csp) csp(GetCurrentThread(), CERF_INPUT_CE_PRIO);
    else     SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
}

static DWORD WINAPI CerfInputPumpThread(LPVOID) {
    HMODULE core = LoadLibraryW(L"coredll.dll");
    PFN_mouse_event me = core
        ? (PFN_mouse_event)GetProcAddressW(core, L"mouse_event") : NULL;
    PFN_keybd_event ke = core
        ? (PFN_keybd_event)GetProcAddressW(core, L"keybd_event") : NULL;
    volatile ULONG* ptr = NULL;
    volatile ULONG* kb  = NULL;
    ULONG last_seq  = 0;
    ULONG last_btn  = 0;
    LONG  last_wheel = 0;
    ULONG consumed  = 0;

    CerfInputBoost(core);
    CERF_LOG_X("cerf_guest: inputpump mouse_event", (DWORD)me);
    CERF_LOG_X("cerf_guest: inputpump keybd_event", (DWORD)ke);

    if (me) {
        ptr = (volatile ULONG*)CerfMapRegsPage(g_CerfVirtBase + CerfVirt::kPointerOffset,
                                               CerfVirt::kPointerSize);
        if (!ptr) me = NULL;
    }
    if (ke) {
        kb = (volatile ULONG*)CerfMapRegsPage(g_CerfVirtBase + CerfVirt::kKeyboardOffset,
                                              CerfVirt::kKeyboardSize);
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
        last_seq   = ptr[CERF_PTR_SEQ / 4];
        last_wheel = (LONG)ptr[CERF_PTR_WHEEL / 4];
    }
    if (ke) consumed = kb[CERF_KB_WRITE_SEQ / 4];

    for (;;) {
        if (me) {
            ULONG seq = ptr[CERF_PTR_SEQ / 4];
            if (seq != last_seq) {
                DWORD nx    = ptr[CERF_PTR_X / 4];
                DWORD ny    = ptr[CERF_PTR_Y / 4];
                ULONG btn   = ptr[CERF_PTR_BUTTONS / 4];
                LONG  wheel = (LONG)ptr[CERF_PTR_WHEEL / 4];
                ULONG changed;
                last_seq = seq;

                me(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE, nx, ny, 0, 0);

                changed = btn ^ last_btn;
                if (changed & 1u) me((btn & 1u) ? MOUSEEVENTF_LEFTDOWN   : MOUSEEVENTF_LEFTUP,   0, 0, 0, 0);
                if (changed & 2u) me((btn & 2u) ? MOUSEEVENTF_RIGHTDOWN  : MOUSEEVENTF_RIGHTUP,  0, 0, 0, 0);
                if (changed & 4u) me((btn & 4u) ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP, 0, 0, 0, 0);
                last_btn = btn;

                if (wheel != last_wheel) {
                    me(MOUSEEVENTF_WHEEL, 0, 0, (DWORD)(wheel - last_wheel), 0);
                    last_wheel = wheel;
                }
            }
        }

        if (ke) {
            ULONG wseq = kb[CERF_KB_WRITE_SEQ / 4];
            while (consumed != wseq) {
                ULONG idx, entry;
                BYTE  vk;
                DWORD flags;
                if ((ULONG)(wseq - consumed) > CERF_KB_RING_COUNT)
                    consumed = wseq - CERF_KB_RING_COUNT;
                idx   = consumed % CERF_KB_RING_COUNT;
                entry = kb[(CERF_KB_RING_BASE / 4) + idx];
                vk    = (BYTE)(entry & CERF_KB_VK_MASK);
                flags = (entry & CERF_KB_KEYUP_BIT) ? KEYEVENTF_KEYUP : 0u;
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
