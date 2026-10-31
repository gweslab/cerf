#include <windows.h>
#include "cerf_coredll_proc.h"
#include "cerf_ddhal_ce5.h"
#include "cerf_display_mode.h"
#include "cerf_display_orientation.h"
#include "cerf_gwes_ready.h"
#include "cerf_resize_pump.h"
#include "main.h"

#include "cerfcore/peripherals/cerf_virt/cerf_virt_resize_regs.h"

typedef enum { kCerfRszIdle, kCerfRszHome } CerfRszPhase;

typedef struct {
    BOOL                         dead;
    BOOL                         resolved;
    BOOL                          ready;
    CerfChangeDisplaySettingsExFn cds;
    ULONG                        last_gen;
    CerfRszPhase                 phase;
    ULONG                        home;
    ULONG                        away;
    BOOL                         waiting;
} CerfRszState;

static CerfRszState s_rsz;

static CerfRszState* Rsz(void) { return &s_rsz; }

static BOOL CerfRszResolve(CerfRszState* z) {
    z->cds = (CerfChangeDisplaySettingsExFn)CerfCoredllProc(L"ChangeDisplaySettingsExW");
    if (!z->cds)
        z->cds = (CerfChangeDisplaySettingsExFn)CerfCoredllProc(L"ChangeDisplaySettingsEx");
    CERF_LOG_X("cerf_guest: rszpump CDS proc", (DWORD)z->cds);
    return z->cds != NULL;
}

static ULONG CerfRszPartner(ULONG dmdo) {
    return CerfDisplayOrientationOfQuarter(CerfDisplayOrientationQuarter(dmdo) + 2u);
}

static BOOL CerfRszTurn(CerfRszState* z, ULONG from, ULONG to, BOOL keep_published) {
    LONG r;
    BOOL turned;
    CerfDisplayModeBeginPumpTurn(from, keep_published);
    r      = CerfDisplayOrientationCall(z->cds, DM_DISPLAYORIENTATION, to, CDS_RESET, NULL);
    turned = CerfDisplayModeEndPumpTurn();
    if (turned && r != DISP_CHANGE_SUCCESSFUL)
        CERF_FATAL("cerf_guest: rszpump gwes failed a turn the driver made");
    if (turned || r == DISP_CHANGE_SUCCESSFUL || r == DISP_CHANGE_FAILED) return turned;
    CERF_LOG_X("cerf_guest: rszpump CDS refused, result", (DWORD)r);
    CerfDisplayModeCancelRequest();
    z->phase = kCerfRszIdle;
    return FALSE;
}

static BOOL CerfRszHomeDone(CerfRszState* z) {
    return CerfRszTurn(z, z->away, z->home, FALSE) || CerfDisplayModeAngle() != z->away ||
           z->phase != kCerfRszHome;
}

static void CerfRszStep(CerfRszState* z) {
    if (z->phase == kCerfRszHome) {
        if (!CerfRszHomeDone(z)) return;
        z->phase = kCerfRszIdle;
    }
    if (!CerfDisplayModeNativePending()) return;
    if (CerfCe5PrimaryHeld()) {
        if (!z->waiting) CERF_LOG("cerf_guest: rszpump live resize waits, the CE 5.0 DirectDraw core holds a primary");
        z->waiting = TRUE;
        return;
    }
    z->waiting = FALSE;
    z->home    = CerfDisplayModeAngle();
    z->away = CerfRszPartner(z->home);
    if (!CerfRszTurn(z, z->home, z->away, TRUE)) return;
    z->phase = kCerfRszHome;
    if (CerfRszHomeDone(z)) z->phase = kCerfRszIdle;
}

extern "C" void CerfResizeTick(void) {
    CerfRszState*   z = Rsz();
    volatile ULONG* regs;
    ULONG           gen;

    if (z->dead) return;

    if (!z->resolved) {
        z->resolved = TRUE;
        if (!CerfRszResolve(z)) {
            CERF_LOG("cerf_guest: rszpump no ChangeDisplaySettingsEx (CE3) - disabled");
            z->dead = TRUE;
            return;
        }
    }

    if (!CerfIsApiReadyAvailable()) {
        CERF_LOG_X("cerf_guest: rszpump SH_WMGR never registered - no resize",
                   CerfShWmgrApiSet());
        z->dead = TRUE;
        return;
    }

    if (!CerfGwesApiSetReady()) return;

    regs = CerfDisplayModeChannel();
    if (!z->ready) {
        if (!regs) {
            CERF_LOG("cerf_guest: rszpump map FAILED");
            z->dead = TRUE;
            return;
        }
        z->last_gen = regs[cerfcore::CerfVirt::kRszWantGen / 4];
        z->ready    = TRUE;
        return;
    }

    gen = regs[cerfcore::CerfVirt::kRszWantGen / 4];
    if (gen != z->last_gen) {
        z->last_gen = gen;
        CerfDisplayModeRequestNative(regs[cerfcore::CerfVirt::kRszWantW / 4],
                                     regs[cerfcore::CerfVirt::kRszWantH / 4]);
    }
    CerfRszStep(z);
}
