#include <windows.h>

#include "cerf_regs_map.h"
#include "cerf_gwes_ready.h"
#include "cerf_window_owner.h"

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"

#define CERF_CW_EVENT         0x00u
#define CERF_CW_APPEARED      1u
#define CERF_CW_DISAPPEARED   2u

#define CERF_CW_POLL_MS    1000u
#define CERF_CW_IDLE_POLLS 600u

static volatile ULONG*  s_cw_regs     = NULL;

/* iPAQ H3600 PPC2000 gwes.exe sub_1EC14 builds the calibration overlay via
   sub_1C360: class L"static", style 0x90000000, w dword_9459C, h dword_945EC;
   sub_1C360 stamps window ownership from GetCallerProcess(). */
static HWND CerfCwFindCalibWindow(void) {
    int  scrW = GetSystemMetrics(SM_CXSCREEN);
    int  scrH = GetSystemMetrics(SM_CYSCREEN);
    HWND w = GetForegroundWindow();
    if (w) w = GetWindow(w, GW_HWNDFIRST);
    for (; w; w = GetWindow(w, GW_HWNDNEXT)) {
        LONG  style;
        RECT  rc;
        WCHAR cls[16];
        style = GetWindowLongW(w, GWL_STYLE);
        if (!(style & WS_VISIBLE)) continue;
        if (!(style & WS_POPUP))   continue;
        if (style & WS_CHILD)      continue;
        if (!GetWindowRect(w, &rc)) continue;
        if (!(rc.left <= 0 && rc.top <= 0 && rc.right >= scrW && rc.bottom >= scrH)) continue;
        cls[0] = 0;
        GetClassNameW(w, cls, 16);
        if (lstrcmpiW(cls, L"static") != 0) continue;
        if (!CerfWindowOwnerIs(w, L"welcome.exe")) continue;
        return w;
    }
    return NULL;
}

static void CerfCwSignal(ULONG event) {
    s_cw_regs[CERF_CW_EVENT / 4] = event;
}

static DWORD WINAPI CerfCwThread(LPVOID) {
    DWORD polls = 0;
    BOOL  present = FALSE;
    BOOL  cycled = FALSE;
    int   miss = 0;
    CERF_LOG("cerf_guest: cwpump thread start");
    CERF_LOG_X("cerf_guest: cwpump SH_WMGR", CerfShWmgrApiSet());

    s_cw_regs = (volatile ULONG*)CerfMapRegsPage(
        g_CerfVirtBase + CerfVirt::kCalibSignalOffset,
        CerfVirt::kCalibSignalSize);
    if (!s_cw_regs) {
        CERF_LOG("cerf_guest: cwpump map FAILED");
        return 0;
    }

    if (!CerfIsApiReadyAvailable()) {
        CERF_LOG("cerf_guest: cwpump coredll has no IsAPIReady - teardown");
        return 0;
    }

    for (;;) {
        HWND cal;
        if (!CerfGwesApiSetReady()) {
            if (++polls > CERF_CW_IDLE_POLLS) {
                CERF_LOG("cerf_guest: cwpump wmgr never ready - teardown");
                break;
            }
            Sleep(CERF_CW_POLL_MS);
            continue;
        }
        cal = CerfCwFindCalibWindow();
        if (cal) {
            miss = 0;
            if (!present) {
                present = TRUE;
                CERF_LOG("cerf_guest: cwpump CALIB APPEARED");
                CerfCwSignal(CERF_CW_APPEARED);
            }
        } else if (present) {
            if (++miss >= 2) {
                present = FALSE;
                miss = 0;
                cycled = TRUE;
                CERF_LOG("cerf_guest: cwpump CALIB DISAPPEARED");
                CerfCwSignal(CERF_CW_DISAPPEARED);
            }
        }
        if (cycled) {
            CERF_LOG("cerf_guest: cwpump cycle complete - teardown");
            break;
        }
        if (!present) {
            if (++polls > CERF_CW_IDLE_POLLS) {
                CERF_LOG("cerf_guest: cwpump idle polls exhausted - teardown");
                break;
            }
        }
        Sleep(CERF_CW_POLL_MS);
    }
    return 0;
}

extern "C" void CerfStartCalibWarningPump(void) {
    static BOOL started = FALSE;
    HANDLE t;
    if (started) return;
    started = TRUE;
    t = CreateThread(NULL, 0, CerfCwThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
}
