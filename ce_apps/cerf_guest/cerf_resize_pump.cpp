#include <windows.h>
#include "cerf_regs_map.h"
#include "cerf_gwes_ready.h"
#include "cerf_resize_pump.h"
#include "main.h"

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"

#define CERF_RSZ_WANT_W       0x00u
#define CERF_RSZ_WANT_H       0x04u
#define CERF_RSZ_WANT_GEN     0x0Cu
#define CERF_RSZ_APPLIED_W    0x10u
#define CERF_RSZ_APPLIED_H    0x14u
#define CERF_RSZ_APPLIED_GEN  0x18u

#ifndef CDS_RESET
#define CDS_RESET 0x40000000u
#endif
#ifndef DISP_CHANGE_SUCCESSFUL
#define DISP_CHANGE_SUCCESSFUL 0
#endif

#ifndef DM_DISPLAYORIENTATION
#define DM_DISPLAYORIENTATION 0x00800000u
#endif
#define CERF_DMDO_OFFSET 188u
#define CERF_DMDO_90      1u
#define CERF_DMDO_270     4u
typedef LONG (WINAPI *PFN_ChangeDisplaySettingsExW)(
    LPCWSTR, DEVMODEW*, HWND, DWORD, LPVOID);

typedef struct {
    volatile ULONG*              regs;
    BOOL                         dead;
    BOOL                         resolved;
    BOOL                         ready;
    PFN_ChangeDisplaySettingsExW cds;
    ULONG                        base_bpp;
    ULONG                        applied_w;
    ULONG                        applied_h;
    ULONG                        last_gen;
    int                          cur;
} CerfRszState;

static CerfRszState s_rsz;

static CerfRszState* Rsz(void) { return &s_rsz; }

static BOOL CerfMapRszRegs(CerfRszState* z) {
    if (z->regs) return TRUE;
    z->regs = (volatile ULONG*)CerfMapRegsPage(g_CerfVirtBase + CerfVirt::kResizeOffset,
                                               CerfVirt::kResizeSize);
    return z->regs != NULL;
}

static BOOL CerfRszResolve(CerfRszState* z) {
    HMODULE h = LoadLibraryW(L"coredll.dll");
    z->cds = h ? (PFN_ChangeDisplaySettingsExW)GetProcAddressW(h, L"ChangeDisplaySettingsExW")
               : NULL;
    if (!z->cds && h)
        z->cds = (PFN_ChangeDisplaySettingsExW)GetProcAddressW(h, L"ChangeDisplaySettingsEx");
    CERF_LOG_X("cerf_guest: rszpump CDS proc", (DWORD)z->cds);
    return z->cds != NULL;
}

extern "C" void CerfResizeTick(void) {
    CerfRszState* z = Rsz();
    ULONG gen;
    DWORD tw, th;
    BYTE  dmbuf[192];
    DEVMODEW* dm;
    LONG r;

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

    if (!z->ready) {
        if (!CerfMapRszRegs(z)) {
            CERF_LOG("cerf_guest: rszpump map FAILED");
            z->dead = TRUE;
            return;
        }
        z->base_bpp  = g_FbBpp;
        z->applied_w = g_FbWidth;
        z->applied_h = g_FbHeight;
        z->last_gen  = z->regs[CERF_RSZ_WANT_GEN / 4];
        z->ready     = TRUE;
        return;
    }

    gen = z->regs[CERF_RSZ_WANT_GEN / 4];
    if (gen == z->last_gen) return;
    z->last_gen = gen;

    tw = z->regs[CERF_RSZ_WANT_W / 4];
    th = z->regs[CERF_RSZ_WANT_H / 4];
    if (tw == 0 || th == 0) return;

    g_FbWidth  = tw;
    g_FbHeight = th;
    g_FbStride = tw * (z->base_bpp >> 3);
    z->cur ^= 1;

    memset(dmbuf, 0, sizeof(dmbuf));
    dm = (DEVMODEW*)dmbuf;
    dm->dmSize   = 192;
    dm->dmFields = DM_DISPLAYORIENTATION;
    *(DWORD*)(dmbuf + CERF_DMDO_OFFSET) = (z->cur == 1) ? CERF_DMDO_270 : CERF_DMDO_90;

    r = z->cds(NULL, dm, NULL, CDS_RESET, NULL);
    CERF_LOG_X("cerf_guest: rszpump CDS result", (DWORD)r);
    if (r == DISP_CHANGE_SUCCESSFUL) {
        z->applied_w = tw;
        z->applied_h = th;
        z->regs[CERF_RSZ_APPLIED_W / 4] = tw;
        z->regs[CERF_RSZ_APPLIED_H / 4] = th;
        z->regs[CERF_RSZ_APPLIED_GEN / 4] =
            z->regs[CERF_RSZ_APPLIED_GEN / 4] + 1;
    } else {
        g_FbWidth  = z->applied_w;
        g_FbHeight = z->applied_h;
        g_FbStride = z->applied_w * (z->base_bpp >> 3);
        z->cur ^= 1;
    }
}
