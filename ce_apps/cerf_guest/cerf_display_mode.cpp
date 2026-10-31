#include "cerf_display_mode.h"

#include "cerf_ddgpe.h"
#include "cerf_ddhal_ce5.h"
#include "cerf_display_orientation.h"
#include "cerf_regs_map.h"
#include "main.h"

#include "cerfcore/peripherals/cerf_virt/cerf_virt_addr_map.h"
#include "cerfcore/peripherals/cerf_virt/cerf_virt_resize_regs.h"

#define CERF_DM_SIZE_BITS 16u
#define CERF_DM_SIZE_MAX  0xFFFFu

typedef struct {
    ULONG           angle;
    volatile DWORD  pump_thread;
    ULONG           pump_from;
    BOOL            pump_keep;
    BOOL            pump_turned;
    LONG            pending;
    volatile ULONG* regs;
} CerfDisplayModeState;

static CerfDisplayModeState s_dm;

static CerfDisplayModeState* Dm(void) { return &s_dm; }

volatile ULONG* CerfDisplayModeChannel(void) {
    CerfDisplayModeState* d = Dm();
    if (!d->regs)
        d->regs = (volatile ULONG*)CerfMapRegsPage(
            g_CerfVirtBase + cerfcore::CerfVirt::kResizeOffset, cerfcore::CerfVirt::kResizeSize);
    return d->regs;
}

static void CerfDmPublish(ULONG quarter) {
    volatile ULONG* regs = CerfDisplayModeChannel();
    if (!regs) {
        CERF_FATAL("cerf_guest: display mode channel map FAILED");
        return;
    }
    regs[cerfcore::CerfVirt::kRszAppliedW / 4]       = g_FbWidth;
    regs[cerfcore::CerfVirt::kRszAppliedH / 4]       = g_FbHeight;
    regs[cerfcore::CerfVirt::kRszAppliedQuarter / 4] = quarter;
    regs[cerfcore::CerfVirt::kRszAppliedGen / 4]     =
        regs[cerfcore::CerfVirt::kRszAppliedGen / 4] + 1u;
}

ULONG CerfDisplayModeRotationCaps(void) {
    return ((ULONG)CERF_DMDO_TURNS << 8) | Dm()->angle;
}

ULONG CerfDisplayModeAngle(void) {
    return Dm()->angle;
}

LONG CerfDisplayModeRotate(ULONG dmdo) {
    CerfDisplayModeState* d = Dm();
    const BOOL pump = d->pump_thread == GetCurrentThreadId();
    LONG pending;
    if (CerfDisplayOrientationOfQuarter(CerfDisplayOrientationQuarter(dmdo)) != dmdo) {
        CERF_LOG_X("cerf_guest: SETSCREENROTATION refused angle", dmdo);
        return DISP_CHANGE_BADMODE;
    }
    if (pump && d->angle != d->pump_from) {
        CERF_LOG_X("cerf_guest: resize turn skipped, display now at DMDO", d->angle);
        return DISP_CHANGE_FAILED;
    }
    pending = CerfCe5PrimaryHeld() ? 0 : InterlockedExchange(&d->pending, 0);
    if (pending) {
        g_FbWidth  = (ULONG)pending >> CERF_DM_SIZE_BITS;
        g_FbHeight = (ULONG)pending & CERF_DM_SIZE_MAX;
        g_FbStride = g_FbWidth * (g_FbBpp >> 3);
    }
    d->angle = dmdo;
    ((CerfDDGPE*)GetGPE())->ApplyFbMode();
    CerfDmPublish(CerfDisplayOrientationQuarter(pump && d->pump_keep ? d->pump_from : dmdo));
    if (pump) d->pump_turned = TRUE;
    CERF_LOG_X("cerf_guest: display turned to DMDO", dmdo);
    return DISP_CHANGE_SUCCESSFUL;
}

void CerfDisplayModeRequestNative(ULONG w, ULONG h) {
    CerfDisplayModeState* d = Dm();
    if (w > CERF_DM_SIZE_MAX || h > CERF_DM_SIZE_MAX) {
        CERF_LOG_X("cerf_guest: display mode refused width", w);
        CERF_LOG_X("cerf_guest: display mode refused height", h);
        return;
    }
    if (w == g_FbWidth && h == g_FbHeight) {
        InterlockedExchange(&d->pending, 0);
        return;
    }
    InterlockedExchange(&d->pending, (LONG)((w << CERF_DM_SIZE_BITS) | h));
}

BOOL CerfDisplayModeNativePending(void) {
    return Dm()->pending != 0;
}

void CerfDisplayModeCancelRequest(void) {
    InterlockedExchange(&Dm()->pending, 0);
}

void CerfDisplayModeBeginPumpTurn(ULONG from, BOOL keep_published) {
    CerfDisplayModeState* d = Dm();
    d->pump_from   = from;
    d->pump_keep   = keep_published;
    d->pump_turned = FALSE;
    d->pump_thread = GetCurrentThreadId();
}

BOOL CerfDisplayModeEndPumpTurn(void) {
    CerfDisplayModeState* d = Dm();
    d->pump_thread = 0;
    return d->pump_turned;
}
