#include <windows.h>

#include "cerf_regs_map.h"
#include "cerf_gwes_ready.h"
#include "cerf_window_owner.h"
#include "cerf_calib_warning_pump.h"

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"

#define CERF_CW_EVENT         0x00u
#define CERF_CW_APPEARED      1u
#define CERF_CW_DISAPPEARED   2u

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

static BOOL  s_cw_dead    = FALSE;
static BOOL  s_cw_ready   = FALSE;
static BOOL  s_cw_present = FALSE;
static DWORD s_cw_polls   = 0;
static int   s_cw_miss    = 0;

extern "C" void CerfCalibWarningTick(void) {
    HWND cal;

    if (s_cw_dead) return;

    if (!s_cw_ready) {
        CERF_LOG_X("cerf_guest: cwpump SH_WMGR", CerfShWmgrApiSet());
        s_cw_regs = (volatile ULONG*)CerfMapRegsPage(
            g_CerfVirtBase + CerfVirt::kCalibSignalOffset,
            CerfVirt::kCalibSignalSize);
        if (!s_cw_regs) {
            CERF_LOG("cerf_guest: cwpump map FAILED");
            s_cw_dead = TRUE;
            return;
        }
        if (!CerfIsApiReadyAvailable()) {
            CERF_LOG("cerf_guest: cwpump coredll has no IsAPIReady - teardown");
            s_cw_dead = TRUE;
            return;
        }
        s_cw_ready = TRUE;
        return;
    }

    if (!CerfGwesApiSetReady()) {
        if (++s_cw_polls > CERF_CW_IDLE_POLLS) {
            CERF_LOG("cerf_guest: cwpump wmgr never ready - teardown");
            s_cw_dead = TRUE;
        }
        return;
    }

    cal = CerfCwFindCalibWindow();
    if (cal) {
        s_cw_miss = 0;
        if (!s_cw_present) {
            s_cw_present = TRUE;
            CERF_LOG("cerf_guest: cwpump CALIB APPEARED");
            CerfCwSignal(CERF_CW_APPEARED);
        }
    } else if (s_cw_present) {
        if (++s_cw_miss >= 2) {
            s_cw_present = FALSE;
            s_cw_miss = 0;
            CERF_LOG("cerf_guest: cwpump CALIB DISAPPEARED");
            CerfCwSignal(CERF_CW_DISAPPEARED);
            CERF_LOG("cerf_guest: cwpump cycle complete - teardown");
            s_cw_dead = TRUE;
            return;
        }
    }

    if (!s_cw_present) {
        if (++s_cw_polls > CERF_CW_IDLE_POLLS) {
            CERF_LOG("cerf_guest: cwpump idle polls exhausted - teardown");
            s_cw_dead = TRUE;
        }
    }
}
