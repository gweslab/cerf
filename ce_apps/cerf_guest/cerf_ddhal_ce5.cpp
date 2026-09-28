#include <windows.h>

#include "include/ddraw_ce6.h"
#include "cerf_ddgpe.h"
#include "cerf_ddgpe_ddhal.h"
#include "cerf_ddhal.h"
#include "cerf_ddhal_ce5.h"
#include "cerf_debug_log.h"
#include "main.h"

#define CE5_LCL_DWRESERVED1_OFF 0x10u
struct Ce5SurfBind { void* lcl; ULONG_PTR surf; };
static Ce5SurfBind s_ce5BindTab[64];

static Ce5SurfBind* Ce5Binds(void) { return s_ce5BindTab; }

static ULONG_PTR* Ce5BindFind(void* lcl) {
    Ce5SurfBind* binds = Ce5Binds();
    for (int i = 0; i < 64; ++i) if (binds[i].lcl == lcl) return &binds[i].surf;
    return NULL;
}

static void Ce5BindForget(void* lcl) {
    Ce5SurfBind* binds = Ce5Binds();
    for (int i = 0; i < 64; ++i)
        if (binds[i].lcl == lcl) { binds[i].lcl = NULL; binds[i].surf = 0; return; }
}

static DWORD Ce5CapsToC6(DWORD ce5) {
    DWORD c6 = 0;
    if (ce5 & 0x00000002u) c6 |= 0x00000001u;
    if (ce5 & 0x00000004u) c6 |= 0x00000002u;
    if (ce5 & 0x00000010u) c6 |= 0x00000004u;
    if (ce5 & 0x00000020u) c6 |= 0x00000008u;
    if (ce5 & 0x00000080u) c6 |= 0x00000010u;
    if (ce5 & 0x00000200u) c6 |= 0x00000040u;
    if (ce5 & 0x00000800u) c6 |= 0x00000080u;
    if (ce5 & 0x00004000u) c6 |= 0x00000100u;
    if (ce5 & 0x00040000u) c6 |= 0x00008000u;
    return c6;
}

static DWORD Ce5CapsAddPlacementFromC6(DWORD ce5orig, DWORD c6) {
    if (c6 & 0x00000100u) ce5orig |= 0x00004000u;
    if (c6 & 0x00000080u) ce5orig |= 0x00000800u;
    return ce5orig;
}

#define CE5_LCL_DDSCAPS_OFF 0x20u
#define CE6_LCL_DDSCAPS_OFF 0x08u
struct Ce5LclSave { ULONG_PTR off8; DWORD ce5caps; };

static void Ce5CreateMarshalIn(void* lcl, Ce5LclSave* s) {
    BYTE* b = (BYTE*)lcl;
    s->off8    = *(ULONG_PTR*)(b + CE6_LCL_DDSCAPS_OFF);
    s->ce5caps = *(DWORD*)(b + CE5_LCL_DDSCAPS_OFF);
    *(DWORD*)(b + CE6_LCL_DDSCAPS_OFF) = Ce5CapsToC6(s->ce5caps);
}

static void Ce5CreateMarshalOut(void* lcl, const Ce5LclSave* s) {
    BYTE* b = (BYTE*)lcl;
    DWORD c6caps = *(DWORD*)(b + CE6_LCL_DDSCAPS_OFF);
    *(DWORD*)(b + CE5_LCL_DDSCAPS_OFF) = Ce5CapsAddPlacementFromC6(s->ce5caps, c6caps);
    *(ULONG_PTR*)(b + CE6_LCL_DDSCAPS_OFF) = s->off8;
}

static ULONG_PTR Ce5LclEnter(void* lcl) {
    if (!lcl) return 0;
    ULONG_PTR* slot = (ULONG_PTR*)((BYTE*)lcl + CE5_LCL_DWRESERVED1_OFF);
    ULONG_PTR ce5val = *slot;
    ULONG_PTR* b = Ce5BindFind(lcl);
    *slot = b ? *b : 0;
    return ce5val;
}

static void Ce5LclLeave(void* lcl, ULONG_PTR ce5val) {
    if (!lcl) return;
    ULONG_PTR* slot = (ULONG_PTR*)((BYTE*)lcl + CE5_LCL_DWRESERVED1_OFF);
    ULONG_PTR surf = *slot;
    ULONG_PTR* b = Ce5BindFind(lcl);
    if (!b) {
        Ce5SurfBind* binds = Ce5Binds();
        for (int i = 0; i < 64; ++i)
            if (!binds[i].lcl) { binds[i].lcl = lcl; b = &binds[i].surf; break; }
    }
    if (b) *b = surf;
    *slot = ce5val;
}

typedef struct _Ce5_DDSURFACEDESC {
    DWORD             dwSize;
    DWORD             dwFlags;
    DWORD             dwHeight;
    DWORD             dwWidth;
    union { LONG lPitch; DWORD dwLinearSize; } u1;
    DWORD             dwBackBufferCount;
    union { DWORD dwMipMapCount; DWORD dwZBufferBitDepth; DWORD dwRefreshRate; } u2;
    DWORD             dwAlphaBitDepth;
    DWORD             dwReserved;
    LPVOID            lpSurface;
    CerfDDCOLORKEY    ddckCKDestOverlay;
    CerfDDCOLORKEY    ddckCKDestBlt;
    CerfDDCOLORKEY    ddckCKSrcOverlay;
    CerfDDCOLORKEY    ddckCKSrcBlt;
    CerfDDPIXELFORMAT ddpfPixelFormat;
    CerfDDSCAPS       ddsCaps;
} Ce5_DDSURFACEDESC;

static void Ce5DescToC6(const Ce5_DDSURFACEDESC* a, Ce6_DDSURFACEDESC* c6) {
    memset(c6, 0, sizeof(*c6));
    c6->dwSize            = sizeof(Ce6_DDSURFACEDESC);
    c6->dwFlags           = a->dwFlags;
    c6->dwHeight          = a->dwHeight;
    c6->dwWidth           = a->dwWidth;
    c6->lPitch            = a->u1.lPitch;
    c6->dwBackBufferCount = a->dwBackBufferCount;
    c6->dwRefreshRate     = a->u2.dwRefreshRate;
    c6->lpSurface         = a->lpSurface;
    c6->ddckCKDestOverlay = a->ddckCKDestOverlay;
    c6->ddckCKDestBlt     = a->ddckCKDestBlt;
    c6->ddckCKSrcOverlay  = a->ddckCKSrcOverlay;
    c6->ddckCKSrcBlt      = a->ddckCKSrcBlt;
    c6->ddpfPixelFormat   = a->ddpfPixelFormat;
    c6->ddsCaps.dwCaps    = Ce5CapsToC6(a->ddsCaps.dwCaps);
}

static void Ce5DescFromC6(Ce5_DDSURFACEDESC* a, const Ce6_DDSURFACEDESC* c6) {

    a->dwFlags         = c6->dwFlags & ~(0x00000010u | 0x00080000u);
    a->dwHeight        = c6->dwHeight;
    a->dwWidth         = c6->dwWidth;
    a->u1.lPitch       = c6->lPitch;
    a->lpSurface       = c6->lpSurface;
    a->ddpfPixelFormat = c6->ddpfPixelFormat;
    a->ddsCaps.dwCaps  = Ce5CapsAddPlacementFromC6(a->ddsCaps.dwCaps, c6->ddsCaps.dwCaps);
}

static DWORD WINAPI Ce5CreateSurfaceWrap(Ce5_DDHAL_CREATESURFACEDATA* pd) {
    Ce5_DDSURFACEDESC* ce5sd = (Ce5_DDSURFACEDESC*)pd->lpDDSurfaceDesc;
    Ce6_DDSURFACEDESC c6sd;
    if (ce5sd) {
        Ce5DescToC6(ce5sd, &c6sd);
        CERF_LOG_X_DEV("cerf_guest: Ce5 CS req ddsCaps", c6sd.ddsCaps.dwCaps);
        CERF_LOG_X_DEV("cerf_guest: Ce5 CS req dwFlags", c6sd.dwFlags);
    }
    Ce6_DDHAL_CREATESURFACEDATA c6;
    c6.lpDD           = (CerfDDrawGbl)pd->lpDD;
    c6.lpDDSurfaceDesc= ce5sd ? &c6sd : NULL;
    c6.dwSCnt         = pd->dwSCnt;
    c6.lplpSList      = (Ce6_DDRAWSURFACE_LCL**)pd->lplpSList;
    c6.ddRVal         = CERF_DD_OK;

    void** sl = (void**)pd->lplpSList;
    DWORD  n  = (pd->dwSCnt < 8u) ? pd->dwSCnt : 8u;
    ULONG_PTR saved10[8] = { 0 };
    Ce5LclSave savedCaps[8] = { 0 };
    for (DWORD i = 0; i < n && sl; ++i)
        if (sl[i]) {
            saved10[i] = *(ULONG_PTR*)((BYTE*)sl[i] + CE5_LCL_DWRESERVED1_OFF);
            Ce5CreateMarshalIn(sl[i], &savedCaps[i]);
        }
    DWORD r = DDGPECreateSurface(&c6);
    for (DWORD j = 0; j < n && sl; ++j)
        if (sl[j]) {
            Ce5LclLeave(sl[j], saved10[j]);
            Ce5CreateMarshalOut(sl[j], &savedCaps[j]);

            ULONG gbl = *(ULONG*)((BYTE*)sl[j] + 0x04u);
            ULONG_PTR* bind = Ce5BindFind(sl[j]);
            ULONG bufva = CerfDDGPESurfBufferVa(bind ? (ULONG)*bind : 0u);
            if (gbl && bufva) *(ULONG*)((BYTE*)(ULONG_PTR)gbl + 0x14u) = bufva;
            CERF_LOG_X_DEV("cerf_guest: Ce5 CS surf fpVidMem set", bufva);
        }
    if (ce5sd) Ce5DescFromC6(ce5sd, &c6sd);
    pd->ddRVal = c6.ddRVal;
    CERF_LOG_X_DEV("cerf_guest: Ce5 CreateSurface ddRVal", (DWORD)c6.ddRVal);
    return r;
}

static DWORD WINAPI Ce5CanCreateSurfaceWrap(Ce5_DDHAL_CREATESURFACEDATA* pd) {
    Ce6_DDHAL_CANCREATESURFACEDATA* in = (Ce6_DDHAL_CANCREATESURFACEDATA*)pd;
    Ce5_DDSURFACEDESC* ce5sd = (Ce5_DDSURFACEDESC*)in->lpDDSurfaceDesc;
    Ce6_DDSURFACEDESC c6sd;
    Ce6_DDHAL_CANCREATESURFACEDATA c6;
    memset(&c6, 0, sizeof(c6));
    c6.lpDD                    = in->lpDD;
    c6.bIsDifferentPixelFormat = in->bIsDifferentPixelFormat;
    if (ce5sd) { Ce5DescToC6(ce5sd, &c6sd); c6.lpDDSurfaceDesc = &c6sd; }
    else       { c6.lpDDSurfaceDesc = NULL; }
    c6.ddRVal = CERF_DD_OK;
    DWORD r = DDGPECanCreateSurface(&c6);
    in->ddRVal = c6.ddRVal;
    CERF_LOG_X_DEV("cerf_guest: Ce5 CanCreateSurface ddRVal", (DWORD)c6.ddRVal);
    return r;
}

static DWORD WINAPI Ce5LockWrap(Ce5_DDHAL_LOCKDATA* pd) {
    Ce6_DDHAL_LOCKDATA c6;
    memset(&c6, 0, sizeof(c6));
    c6.lpDD       = (CerfDDrawGbl)pd->lpDD;
    c6.lpDDSurface= (Ce6_DDRAWSURFACE_LCL*)pd->lpDDSurface;
    c6.bHasRect   = pd->bHasRect;
    memcpy(&c6.rArea, &pd->rArea, sizeof(c6.rArea));
    c6.dwFlags    = pd->dwFlags;
    ULONG_PTR sv = Ce5LclEnter(pd->lpDDSurface);
    DWORD r = CerfDDGPELockWrap(&c6);
    Ce5LclLeave(pd->lpDDSurface, sv);
    pd->lpSurfData = c6.lpSurfData;
    pd->ddRVal     = c6.ddRVal;
    return r;
}

typedef struct _Ce5_DDHAL_BLTDATA {
    PVOID       lpDD;
    PVOID       lpDDDestSurface;
    RECTL       rDest;
    PVOID       lpDDSrcSurface;
    RECTL       rSrc;
    DWORD       dwFlags;
    DWORD       dwROPFlags;
    CerfDDBLTFX bltFX;
    HRESULT     ddRVal;
} Ce5_DDHAL_BLTDATA;

static DWORD WINAPI Ce5BltWrap(Ce5_DDHAL_BLTDATA* pd) {
    ULONG_PTR svD = Ce5LclEnter(pd->lpDDDestSurface);
    ULONG_PTR svS = Ce5LclEnter(pd->lpDDSrcSurface);
    int ok = CerfDDrawBlt(pd->lpDDDestSurface, pd->lpDDSrcSurface,
                          &pd->rDest, &pd->rSrc, pd->dwFlags,
                          pd->bltFX.dwROP, pd->bltFX.dwFillColor,
                          pd->bltFX.ddckSrcColorkey.dwColorSpaceLowValue);
    Ce5LclLeave(pd->lpDDSrcSurface, svS);
    Ce5LclLeave(pd->lpDDDestSurface, svD);
    pd->ddRVal = ok ? CERF_DD_OK : CERF_DDERR_GENERIC;
    return DDHAL_DRIVER_HANDLED;
}

static DWORD WINAPI Ce5DestroySurfaceWrap(Ce6_DDHAL_DESTROYSURFACEDATA* pd) {
    ULONG_PTR sv = Ce5LclEnter(pd->lpDDSurface);
    DWORD r = DDGPEDestroySurface(pd);
    Ce5LclLeave(pd->lpDDSurface, sv);
    Ce5BindForget(pd->lpDDSurface);
    CERF_LOG_X_DEV("cerf_guest: Ce5 DestroySurface ddRVal", (DWORD)pd->ddRVal);
    return r;
}

static DWORD WINAPI Ce5FlipWrap(Ce6_DDHAL_FLIPDATA* pd) {

    ULONG_PTR svC = Ce5LclEnter(pd->lpSurfCurr);
    ULONG_PTR svT = Ce5LclEnter(pd->lpSurfTarg);
    DWORD r = DDGPEFlip(pd);
    Ce5LclLeave(pd->lpSurfTarg, svT);
    Ce5LclLeave(pd->lpSurfCurr, svC);
    return r;
}

static DWORD WINAPI Ce5SetColorKeyWrap(Ce6_DDHAL_SETCOLORKEYDATA* pd) {
    ULONG_PTR sv = Ce5LclEnter(pd->lpDDSurface);
    DWORD r = DDGPESetColorKey(pd);
    Ce5LclLeave(pd->lpDDSurface, sv);
    CERF_LOG_X_DEV("cerf_guest: Ce5 SetColorKey ddRVal", (DWORD)pd->ddRVal);
    return r;
}

typedef struct _Ce5_DDHAL_WAITFORVERTICALBLANKDATA {
    PVOID     lpDD;
    DWORD     dwFlags;
    DWORD     bIsInVB;
    ULONG_PTR hEvent;
    HRESULT   ddRVal;
} Ce5_DDHAL_WAITFORVERTICALBLANKDATA;

static DWORD WINAPI Ce5WaitForVBlankWrap(Ce5_DDHAL_WAITFORVERTICALBLANKDATA* pd) {
    Ce6_DDHAL_WAITFORVERTICALBLANKDATA c6;
    memset(&c6, 0, sizeof(c6));
    c6.lpDD    = (CerfDDrawGbl)pd->lpDD;
    c6.dwFlags = pd->dwFlags;
    DWORD r = DDGPEWaitForVerticalBlank(&c6);
    pd->bIsInVB = c6.bIsInVB;
    pd->ddRVal  = c6.ddRVal;
    return r;
}

static Ce5_DDHAL_DDCALLBACKS g_ce5DDCallbacks = {
    sizeof(Ce5_DDHAL_DDCALLBACKS),

    0x00000002u | 0x00000020u | 0x00000010u | 0x00000040u,
    NULL,
    (PVOID)Ce5CreateSurfaceWrap,
    NULL,
    NULL,
    (PVOID)Ce5WaitForVBlankWrap,
    (PVOID)Ce5CanCreateSurfaceWrap,
    (PVOID)DDGPECreatePalette,
    NULL,
    NULL,
    NULL
};

static Ce5_DDHAL_DDSURFACECALLBACKS g_ce5SurfCallbacks = {
    sizeof(Ce5_DDHAL_DDSURFACECALLBACKS),

    0x1u | 0x2u | 0x8u | 0x10u | 0x20u | 0x40u | 0x100u | 0x200u | 0x2000u,
    (PVOID)Ce5DestroySurfaceWrap,
    (PVOID)Ce5FlipWrap,
    NULL,
    (PVOID)Ce5LockWrap,
    (PVOID)CerfDDGPEUnlockWrap,
    (PVOID)Ce5BltWrap,
    (PVOID)Ce5SetColorKeyWrap,
    NULL,
    (PVOID)CerfGetBltStatus,
    (PVOID)DDGPEGetFlipStatus,
    NULL,
    NULL,
    NULL,
    (PVOID)DDGPESetPalette,
    NULL,
    NULL
};

#define CE5_DDSCAPS_BACKBUFFER     0x00000004u
#define CE5_DDSCAPS_FLIP           0x00000010u
#define CE5_DDSCAPS_FRONTBUFFER    0x00000020u
#define CE5_DDSCAPS_PRIMARYSURFACE 0x00000200u
#define CE5_DDSCAPS_SYSTEMMEMORY   0x00000800u
#define CE5_DDSCAPS_VIDEOMEMORY    0x00004000u

extern "C" BOOL Ce5HALInit(void* lpddhi) {
    if (sizeof(Ce5_DDHALINFO) != 460u) {
        CERF_LOG_X("cerf_guest: Ce5HALInit BAD sizeof(Ce5_DDHALINFO)",
                   (DWORD)sizeof(Ce5_DDHALINFO));
        return FALSE;
    }
    unsigned long vidSize = 0, vidFree = 0;
    CerfGetVideoMem(NULL, &vidSize, &vidFree);

    Ce5_DDHALINFO* h = (Ce5_DDHALINFO*)lpddhi;
    memset(h, 0, sizeof(Ce5_DDHALINFO));
    h->dwSize               = sizeof(Ce5_DDHALINFO);
    h->lpDDCallbacks        = &g_ce5DDCallbacks;
    h->lpDDSurfaceCallbacks = &g_ce5SurfCallbacks;
    h->lpDDPaletteCallbacks = NULL;

    h->vmiData.fpPrimary       = CerfGpeFbMemBasePa();
    h->vmiData.dwDisplayWidth  = g_FbWidth;
    h->vmiData.dwDisplayHeight = g_FbHeight;
    h->vmiData.lDisplayPitch   = (LONG)g_FbStride;
    h->vmiData.ddpfDisplay.dwSize        = sizeof(Ce5_DDPIXELFORMAT);
    h->vmiData.ddpfDisplay.dwFlags       = CERF_DDPF_RGB;
    h->vmiData.ddpfDisplay.dwRGBBitCount = g_FbBpp;
    if (g_FbBpp == 16) {
        h->vmiData.ddpfDisplay.dwRBitMask = 0xF800u;
        h->vmiData.ddpfDisplay.dwGBitMask = 0x07E0u;
        h->vmiData.ddpfDisplay.dwBBitMask = 0x001Fu;
    } else {
        h->vmiData.ddpfDisplay.dwRBitMask = 0x00FF0000u;
        h->vmiData.ddpfDisplay.dwGBitMask = 0x0000FF00u;
        h->vmiData.ddpfDisplay.dwBBitMask = 0x000000FFu;
    }
    h->vmiData.dwNumHeaps = 0;
    h->vmiData.pvmList    = 0;

    h->ddCaps.dwSize        = sizeof(Ce5_DDCORECAPS);
    h->ddCaps.dwVidMemTotal = vidSize;
    h->ddCaps.dwVidMemFree  = vidFree;

    h->ddCaps.dwCaps = 0x40u  | 0x80000000u ;
    h->ddCaps.ddsCaps.dwCaps =
        CE5_DDSCAPS_PRIMARYSURFACE | CE5_DDSCAPS_FRONTBUFFER | CE5_DDSCAPS_BACKBUFFER |
        CE5_DDSCAPS_FLIP | CE5_DDSCAPS_SYSTEMMEMORY | CE5_DDSCAPS_VIDEOMEMORY;
    h->ddCaps.dwCKeyCaps = CERF_DDCKEYCAPS_SRCBLT;
    CERF_SETROPBIT(h->ddCaps.dwRops, SRCCOPY);
    CERF_SETROPBIT(h->ddCaps.dwRops, PATCOPY);
    CERF_SETROPBIT(h->ddCaps.dwRops, BLACKNESS);
    CERF_SETROPBIT(h->ddCaps.dwRops, WHITENESS);

    static Ce5_DDHALMODEINFO s_modeInfo;
    s_modeInfo.dwWidth        = g_FbWidth;
    s_modeInfo.dwHeight       = g_FbHeight;
    s_modeInfo.lPitch         = (LONG)g_FbStride;
    s_modeInfo.dwBPP          = g_FbBpp;
    s_modeInfo.wFlags         = 0;
    s_modeInfo.wRefreshRate   = (WORD)g_FbRefreshRate;
    s_modeInfo.dwRBitMask     = h->vmiData.ddpfDisplay.dwRBitMask;
    s_modeInfo.dwGBitMask     = h->vmiData.ddpfDisplay.dwGBitMask;
    s_modeInfo.dwBBitMask     = h->vmiData.ddpfDisplay.dwBBitMask;
    s_modeInfo.dwAlphaBitMask = 0;
    h->dwNumModes = 1;
    h->lpModeInfo = &s_modeInfo;

    h->GetDriverInfo = (PVOID)CerfHalGetDriverInfo;
    return TRUE;
}
