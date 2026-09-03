#include <windows.h>
#include "cerf_regs_map.h"
#include "cerf_gwes_ready.h"
#include "cerf_resize_pump.h"

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

extern ULONG g_FbWidth, g_FbHeight, g_FbBpp, g_FbStride;

static volatile ULONG* s_rsz_regs = NULL;

static BOOL CerfMapRszRegs(void) {
    if (s_rsz_regs) return TRUE;
    s_rsz_regs = (volatile ULONG*)CerfMapRegsPage(g_CerfVirtBase + CerfVirt::kResizeOffset,
                                                  CerfVirt::kResizeSize);
    return s_rsz_regs != NULL;
}

static BOOL  s_rsz_dead     = FALSE;
static BOOL  s_rsz_resolved = FALSE;
static BOOL  s_rsz_ready    = FALSE;
static PFN_ChangeDisplaySettingsExW s_cds = NULL;

static ULONG s_base_bpp  = 0;
static ULONG s_applied_w = 0;
static ULONG s_applied_h = 0;
static ULONG s_last_gen  = 0;
static int   s_cur       = 0;

static BOOL CerfRszResolve(void) {
    HMODULE h = LoadLibraryW(L"coredll.dll");
    s_cds = h ? (PFN_ChangeDisplaySettingsExW)GetProcAddressW(h, L"ChangeDisplaySettingsExW")
              : NULL;
    if (!s_cds && h)
        s_cds = (PFN_ChangeDisplaySettingsExW)GetProcAddressW(h, L"ChangeDisplaySettingsEx");
    CERF_LOG_X("cerf_guest: rszpump CDS proc", (DWORD)s_cds);
    return s_cds != NULL;
}

extern "C" void CerfResizeTick(void) {
    ULONG gen;
    DWORD tw, th;
    BYTE  dmbuf[192];
    DEVMODEW* dm;
    LONG r;

    if (s_rsz_dead) return;

    if (!s_rsz_resolved) {
        s_rsz_resolved = TRUE;
        if (!CerfRszResolve()) {
            CERF_LOG("cerf_guest: rszpump no ChangeDisplaySettingsEx (CE3) - disabled");
            s_rsz_dead = TRUE;
            return;
        }
    }

    if (!CerfIsApiReadyAvailable()) {
        CERF_LOG_X("cerf_guest: rszpump SH_WMGR never registered - no resize",
                   CerfShWmgrApiSet());
        s_rsz_dead = TRUE;
        return;
    }

    if (!CerfGwesApiSetReady()) return;

    if (!s_rsz_ready) {
        if (!CerfMapRszRegs()) {
            CERF_LOG("cerf_guest: rszpump map FAILED");
            s_rsz_dead = TRUE;
            return;
        }
        s_base_bpp  = g_FbBpp;
        s_applied_w = g_FbWidth;
        s_applied_h = g_FbHeight;
        s_last_gen  = s_rsz_regs[CERF_RSZ_WANT_GEN / 4];
        s_rsz_ready = TRUE;
        return;
    }

    gen = s_rsz_regs[CERF_RSZ_WANT_GEN / 4];
    if (gen == s_last_gen) return;
    s_last_gen = gen;

    tw = s_rsz_regs[CERF_RSZ_WANT_W / 4];
    th = s_rsz_regs[CERF_RSZ_WANT_H / 4];
    if (tw == 0 || th == 0) return;

    g_FbWidth  = tw;
    g_FbHeight = th;
    g_FbStride = tw * (s_base_bpp >> 3);
    s_cur ^= 1;

    memset(dmbuf, 0, sizeof(dmbuf));
    dm = (DEVMODEW*)dmbuf;
    dm->dmSize   = 192;
    dm->dmFields = DM_DISPLAYORIENTATION;
    *(DWORD*)(dmbuf + CERF_DMDO_OFFSET) = (s_cur == 1) ? CERF_DMDO_270 : CERF_DMDO_90;

    r = s_cds(NULL, dm, NULL, CDS_RESET, NULL);
    CERF_LOG_X("cerf_guest: rszpump CDS result", (DWORD)r);
    if (r == DISP_CHANGE_SUCCESSFUL) {
        s_applied_w = tw;
        s_applied_h = th;
        s_rsz_regs[CERF_RSZ_APPLIED_W / 4] = tw;
        s_rsz_regs[CERF_RSZ_APPLIED_H / 4] = th;
        s_rsz_regs[CERF_RSZ_APPLIED_GEN / 4] =
            s_rsz_regs[CERF_RSZ_APPLIED_GEN / 4] + 1;
    } else {
        g_FbWidth  = s_applied_w;
        g_FbHeight = s_applied_h;
        g_FbStride = s_applied_w * (s_base_bpp >> 3);
        s_cur ^= 1;
    }
}
