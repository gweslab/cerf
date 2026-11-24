#include <windows.h>
#include "cerf_ddhal_wp7.h"
#include "cerf_ddgpe.h"
#include "cerf_ddgpe_ddhal.h"
#include "cerf_ddhal.h"
#include "cerf_debug_log.h"
#include "cerf_wp7_coredll.h"
#include "cerf_wp7_yuv.h"
#include "include/ddraw_ce6.h"
#include "include/ddraw_wp7.h"

#define CERF_WP7_LOCKFLAG_QUERY_ONLY 2
#define CERF_WP7_PFN_QUERY_BYTES     4
#define CERF_WP7_E_NOTIMPL           ((HRESULT)0x80004001L)
#define CERF_WP7_DDPF_ALPHAPIXELS    0x00000001

static DWORD CerfWp7Align(DWORD v) {
    return (v + WP7_SURFACE_ALIGN - 1) & ~(DWORD)(WP7_SURFACE_ALIGN - 1);
}

DWORD CerfWp7RgbStride(DWORD width, DWORD bpp) { return CerfWp7Align(width) * (bpp / 8); }

DWORD CerfWp7RgbSurfaceBytes(DWORD width, DWORD height, DWORD bpp) {
    return CerfWp7Align(height) * CerfWp7RgbStride(width, bpp);
}

static DWORD CerfWp7SurfaceBpp(const Wp7_DDSURFACEDESC* d) {
    const CerfDDPIXELFORMAT* pf = &d->ddpfPixelFormat;
    if (pf->dwFlags & CERF_DDPF_FOURCC) return 0;
    const DWORD alpha  = (pf->dwFlags & CERF_WP7_DDPF_ALPHAPIXELS) ? pf->dwRGBAlphaBitMask : 0u;
    const BOOL  rgb888 = pf->dwRBitMask == 0x00FF0000u && pf->dwGBitMask == 0x0000FF00u &&
                         pf->dwBBitMask == 0x000000FFu;
    switch (pf->dwRGBBitCount) {
        case 16:
            return (alpha == 0u && pf->dwRBitMask == 0xF800u && pf->dwGBitMask == 0x07E0u &&
                    pf->dwBBitMask == 0x001Fu) ? 16 : 0;
        case 24: return (alpha == 0u && rgb888) ? 24 : 0;
        case 32: return ((alpha == 0u || alpha == 0xFF000000u) && rgb888) ? 32 : 0;
        case 0: break;
        default: return 0;
    }
    DDGPESurf* primary = ((CerfDDGPE*)GetGPE())->DDGPEPrimarySurface();
    return primary ? (DWORD)CerfFormatBpp(primary->Format()) : 0;
}

static DWORD WINAPI Wp7CanCreateSurface(Ce6_DDHAL_CANCREATESURFACEDATA* pd) {
    Wp7_DDSURFACEDESC* d = (Wp7_DDSURFACEDESC*)pd->lpDDSurfaceDesc;
    if (d->ddpfPixelFormat.dwFlags & CERF_DDPF_FOURCC) {
        CerfWp7Layout layout;
        if (!CerfWp7YuvLayout(d->ddpfPixelFormat.dwFourCC, d->dwWidth, d->dwHeight, &layout)) {
            CERF_LOG_X_DEV("cerf_guest: WP7 CanCreateSurface refused FourCC", d->ddpfPixelFormat.dwFourCC);
            pd->ddRVal = CERF_DDERR_UNSUPPORTEDFORMAT;
            return DDHAL_DRIVER_HANDLED;
        }
        CerfWp7DescribeLayout(d, &layout);
        pd->ddRVal = CERF_DD_OK;
        return DDHAL_DRIVER_HANDLED;
    }
    const DWORD bpp = CerfWp7SurfaceBpp(d);
    if (bpp == 0) {
        CERF_LOG_X_DEV("cerf_guest: WP7 CanCreateSurface refused pixel format flags",
                       d->ddpfPixelFormat.dwFlags);
        pd->ddRVal = CERF_DDERR_UNSUPPORTEDFORMAT;
        return DDHAL_DRIVER_HANDLED;
    }
    d->dwFlags      |= WP7_DDSD_SURFACE_LAYOUT;
    d->lPitch        = (LONG)CerfWp7RgbStride(d->dwWidth, bpp);
    d->lXPitch       = (LONG)(bpp / 8);
    d->dwSurfaceSize = CerfWp7RgbSurfaceBytes(d->dwWidth, d->dwHeight, bpp);
    memset(d->dwPlaneLayout, 0, sizeof(d->dwPlaneLayout));
    pd->ddRVal = CERF_DD_OK;
    return DDHAL_DRIVER_HANDLED;
}

static DWORD CerfWp7ClientPa(const Wp7_DDSURFACEDESC* d) {
    DWORD pa = 0;
    if ((d->ddsCaps.dwCaps & CE6_DDSCAPS_FLIP) &&
        !CerfWp7Api()->lock_pages(d->lpSurface, CERF_WP7_PFN_QUERY_BYTES, &pa, CERF_WP7_LOCKFLAG_QUERY_ONLY))
        pa = 0;
    return pa;
}

static void Wp7CreateYuvSurface(Ce6_DDHAL_CREATESURFACEDATA* pd, Wp7_DDSURFACEDESC* d) {
    CerfWp7Layout layout;
    if (!CerfWp7YuvLayout(d->ddpfPixelFormat.dwFourCC, d->dwWidth, d->dwHeight, &layout)) {
        pd->ddRVal = CERF_DDERR_UNSUPPORTEDFORMAT;
        return;
    }
    CerfDDGPE*  gpe    = (CerfDDGPE*)GetGPE();
    const BOOL  client = (d->dwFlags & CE6_DDSD_LPSURFACE) != 0;
    GPESurf*    s      = NULL;
    DWORD       pa     = 0;
    if (client) {
        s = new DDGPESurf((int)d->dwWidth, (int)d->dwHeight, d->lpSurface, (int)layout.stride,
                          gpe16YCrCb, CerfFormatToDDGPE(gpe16YCrCb));
        if (s && !s->Buffer()) {
            delete s;
            s = NULL;
        }
        pa = CerfWp7ClientPa(d);
    } else if (FAILED(gpe->AllocVideoBlock(&s, (int)d->dwWidth, (int)d->dwHeight, (int)layout.stride,
                                           layout.size, gpe16YCrCb))) {
        s = NULL;
    } else if (!gpe->SurfaceFbPa(s, &pa)) {
        pa = 0;
    }
    if (!s) {
        pd->ddRVal = client ? CERF_DDERR_OUTOFMEMORY : CERF_DDERR_OUTOFVIDEOMEMORY;
        return;
    }
    DDGPESurf* ds = (DDGPESurf*)s;
    ds->SetYuvPlanes(layout.code, layout.cb_offset, layout.cr_offset, layout.cb_stride);
    ds->SetPhysicalMemory(pa, layout.size);
    ds->SetDDGPESurf(pd->lplpSList[0]);
    pd->lplpSList[0]->ddsCaps.dwCaps |= s->InVideoMemory() ? CE6_DDSCAPS_VIDEOMEMORY : CE6_DDSCAPS_SYSTEMMEMORY;
    CerfWp7DescribeLayout(d, &layout);
    pd->ddRVal = CERF_DD_OK;
}

static DWORD WINAPI Wp7CreateSurface(Ce6_DDHAL_CREATESURFACEDATA* pd) {
    if (pd->dwSCnt != 1) {
        pd->ddRVal = CERF_WP7_E_NOTIMPL;
        return DDHAL_DRIVER_HANDLED;
    }
    Wp7_DDSURFACEDESC* d = (Wp7_DDSURFACEDESC*)pd->lpDDSurfaceDesc;
    if (d->ddpfPixelFormat.dwFlags & CERF_DDPF_FOURCC) {
        Wp7CreateYuvSurface(pd, d);
        return DDHAL_DRIVER_HANDLED;
    }
    const BOOL         client       = (d->dwFlags & CE6_DDSD_LPSURFACE) != 0;
    const DWORD        client_bytes = d->dwSurfaceSize;
    DDGPECreateSurface(pd);
    if (pd->ddRVal != CERF_DD_OK) return DDHAL_DRIVER_HANDLED;

    DDGPESurf* s  = DDGPESurf::GetDDGPESurf(pd->lplpSList[0]);
    const DWORD pa = client ? CerfWp7ClientPa(d) : 0;
    s->SetPhysicalMemory(pa, client ? client_bytes : s->SurfaceBytes());
    d->dwFlags      |= WP7_DDSD_SURFACE_LAYOUT;
    d->dwSurfaceSize = s->SurfaceBytes();
    if (!client) memset(d->dwPlaneLayout, 0, sizeof(d->dwPlaneLayout));
    return DDHAL_DRIVER_HANDLED;
}

static Wp7_DDHAL_DDCALLBACKS g_cbWp7DDCallbacks = {
    sizeof(Wp7_DDHAL_DDCALLBACKS),
    WP7_DDHAL_CB32_CREATESURFACE | WP7_DDHAL_CB32_CANCREATESURFACE,
    (PVOID)Wp7CreateSurface,
    (PVOID)Wp7CanCreateSurface
};

static Wp7_DDHAL_DDSURFACECALLBACKS g_cbWp7DDSurfaceCallbacks = {
    sizeof(Wp7_DDHAL_DDSURFACECALLBACKS),
    WP7_DDHAL_SURFCB32_DESTROYSURFACE | WP7_DDHAL_SURFCB32_LOCK | WP7_DDHAL_SURFCB32_UNLOCK,
    (PVOID)DDGPEDestroySurface,
    (PVOID)CerfDDGPELockWrap,
    (PVOID)DDGPEUnlock,
    NULL
};

static void CerfFillWp7Caps(Wp7_DDCAPS* caps, DWORD surface_caps) {
    memset(caps, 0, sizeof(Wp7_DDCAPS));
    caps->dwSize         = sizeof(Wp7_DDCAPS);
    caps->ddsCaps.dwCaps = surface_caps;
    caps->dwBltCaps      = CERF_DDBLTCAPS_READSYSMEM | CERF_DDBLTCAPS_WRITESYSMEM;
    caps->dwCKeyCaps     = CERF_DDCKEYCAPS_SRCBLT;
    CERF_SETROPBIT(caps->dwRops, SRCCOPY);
    CERF_SETROPBIT(caps->dwRops, PATCOPY);
    CERF_SETROPBIT(caps->dwRops, BLACKNESS);
    CERF_SETROPBIT(caps->dwRops, WHITENESS);
}

static DWORD WINAPI Wp7GetDriverInfo(Ce6_DDHAL_GETDRIVERINFODATA* pd) {
    pd->ddRVal = CERF_DDERR_CURRENTLYNOTAVAIL;
    return DDHAL_DRIVER_HANDLED;
}

extern "C" BOOL Wp7HALInit(void* lpddhi) {
    Wp7_DDHALINFO* h = (Wp7_DDHALINFO*)lpddhi;
    memset(h, 0, sizeof(Wp7_DDHALINFO));
    h->dwSize               = sizeof(Wp7_DDHALINFO);
    h->dwFlags              = WP7_DDHALINFO_FOURCC_RECORDS;
    h->lpDDCallbacks        = &g_cbWp7DDCallbacks;
    h->lpDDSurfaceCallbacks = &g_cbWp7DDSurfaceCallbacks;
    h->GetDriverInfo        = (PVOID)Wp7GetDriverInfo;
    CerfFillWp7Caps(&h->ddCaps, WP7_STOCK_DRIVER_SURFACE_CAPS);
    CerfFillWp7Caps(&h->ddHelCaps, WP7_STOCK_HEL_SURFACE_CAPS);
    h->lpdwFourCC = (PVOID)CerfWp7FourCcFormats(&h->ddCaps.dwNumFourCCCodes);
    return TRUE;
}
