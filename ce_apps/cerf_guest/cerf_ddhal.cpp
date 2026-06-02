#include <windows.h>
#include <winddi.h>
#include <gpe.h>
#include <ddgpe.h>   /* brings in ddrawi.h (DDHALINFO, DDHAL_DD*CALLBACKS) */

extern ULONG g_EngineVersion;
extern "C" void CerfGetVideoMem(unsigned long* base, unsigned long* size,
                                unsigned long* freeBytes);

/* Generic DDGPE framework surface/device callbacks (ddgpe.lib, ddhsurf.cpp).
   cerf_guest wires its DDHALINFO straight at these — no DSS/overlay Hal*
   wrappers, since the CERF framebuffer is software. */
extern "C" DWORD WINAPI DDGPECreateSurface(LPDDHAL_CREATESURFACEDATA);
extern "C" DWORD WINAPI DDGPECanCreateSurface(LPDDHAL_CANCREATESURFACEDATA);
extern "C" DWORD WINAPI DDGPEDestroySurface(LPDDHAL_DESTROYSURFACEDATA);
extern "C" DWORD WINAPI DDGPEFlip(LPDDHAL_FLIPDATA);
extern "C" DWORD WINAPI DDGPELock(LPDDHAL_LOCKDATA);
extern "C" DWORD WINAPI DDGPEUnlock(LPDDHAL_UNLOCKDATA);
extern "C" DWORD WINAPI DDGPESetColorKey(LPDDHAL_SETCOLORKEYDATA);
extern "C" DWORD WINAPI DDGPEGetFlipStatus(LPDDHAL_GETFLIPSTATUSDATA);
extern "C" DWORD WINAPI DDGPESetPalette(LPDDHAL_SETPALETTEDATA);

/* Diagnostic wrappers: log whether the kernel reaches the HAL for each surface
   create + what it answers, to settle why a system-memory (DDSD_LPSURFACE)
   surface gets E_NOTIMPL while a video surface succeeds. Delegate to the generic
   DDGPE* lib (the path stock HalCreateSurface uses for system memory). */
static DWORD WINAPI CerfCreateSurface(LPDDHAL_CREATESURFACEDATA pd) {
    DWORD caps  = pd->lpDDSurfaceDesc ? pd->lpDDSurfaceDesc->ddsCaps.dwCaps : 0;
    DWORD flags = pd->lpDDSurfaceDesc ? pd->lpDDSurfaceDesc->dwFlags : 0;
    CERF_LOG_X("cerf_guest: HAL CreateSurface caps", caps);
    CERF_LOG_X("cerf_guest: HAL CreateSurface dwFlags", flags);
    DWORD r = DDGPECreateSurface(pd);
    CERF_LOG_X("cerf_guest: HAL CreateSurface ddRVal", (DWORD)pd->ddRVal);
    CERF_LOG_X("cerf_guest: HAL CreateSurface result", r);
    return r;
}
static DWORD WINAPI CerfCanCreateSurface(LPDDHAL_CANCREATESURFACEDATA pd) {
    DWORD caps  = pd->lpDDSurfaceDesc ? pd->lpDDSurfaceDesc->ddsCaps.dwCaps : 0;
    CERF_LOG_X("cerf_guest: HAL CanCreateSurface caps", caps);
    DWORD r = DDGPECanCreateSurface(pd);
    CERF_LOG_X("cerf_guest: HAL CanCreateSurface ddRVal", (DWORD)pd->ddRVal);
    return r;
}

/* Field order + flags per ce6-oak ddrawi.h: DDHAL_DDCALLBACKS:713,
   DDHAL_DDSURFACECALLBACKS:747. */
static DDHAL_DDCALLBACKS g_cbDDCallbacks = {
    sizeof(DDHAL_DDCALLBACKS),
    DDHAL_CB32_CREATESURFACE | DDHAL_CB32_CANCREATESURFACE,
    CerfCreateSurface,         /* CreateSurface */
    NULL,                      /* WaitForVerticalBlank */
    CerfCanCreateSurface,      /* CanCreateSurface */
    NULL,                      /* CreatePalette */
    NULL                       /* GetScanLine */
};

static DDHAL_DDSURFACECALLBACKS g_cbDDSurfaceCallbacks = {
    sizeof(DDHAL_DDSURFACECALLBACKS),
    DDHAL_SURFCB32_DESTROYSURFACE | DDHAL_SURFCB32_FLIP | DDHAL_SURFCB32_LOCK |
        DDHAL_SURFCB32_UNLOCK | DDHAL_SURFCB32_SETCOLORKEY |
        DDHAL_SURFCB32_GETFLIPSTATUS | DDHAL_SURFCB32_SETPALETTE,
    DDGPEDestroySurface,       /* DestroySurface */
    DDGPEFlip,                 /* Flip */
    DDGPELock,                 /* Lock */
    DDGPEUnlock,               /* Unlock */
    DDGPESetColorKey,          /* SetColorKey */
    NULL,                      /* GetBltStatus */
    DDGPEGetFlipStatus,        /* GetFlipStatus */
    NULL,                      /* UpdateOverlay */
    NULL,                      /* SetOverlayPosition */
    DDGPESetPalette            /* SetPalette */
};

/* Answers the DirectDraw VidMemBase query with the offscreen base the driver
   advertises (mirrors omap halcaps.cpp HalGetDriverInfo, VidMemBase arm). */
static DWORD WINAPI CerfHalGetDriverInfo(LPDDHAL_GETDRIVERINFODATA lpInput) {
    lpInput->ddRVal = DDERR_CURRENTLYNOTAVAIL;
    if (IsEqualIID(lpInput->guidInfo, GUID_GetDriverInfo_VidMemBase)) {
        unsigned long base = 0, size = 0, freeBytes = 0;
        CerfGetVideoMem(&base, &size, &freeBytes);
        *(DWORD*)(lpInput->lpvData) = base;
        lpInput->dwActualSize = sizeof(DWORD);
        lpInput->ddRVal = DD_OK;
        CERF_LOG_X("cerf_guest: HalGetDriverInfo VidMemBase", base);
    }
    return DDHAL_DRIVER_HANDLED;
}

/* Driver-provided; the lib's HALInit (ddhinit.cpp:102) calls this. Mirrors omap
   halcaps.cpp buildDDHALInfo, minus DSS/overlay: advertise the real offscreen
   video-memory region the driver carves surfaces from. */
EXTERN_C void buildDDHALInfo(LPDDHALINFO lpddhi, DWORD modeidx) {
    unsigned long vidBase = 0, vidSize = 0, vidFree = 0;
    CerfGetVideoMem(&vidBase, &vidSize, &vidFree);

    memset(lpddhi, 0, sizeof(DDHALINFO));
    lpddhi->dwSize               = sizeof(DDHALINFO);
    lpddhi->lpDDCallbacks        = &g_cbDDCallbacks;
    lpddhi->lpDDSurfaceCallbacks = &g_cbDDSurfaceCallbacks;
    lpddhi->GetDriverInfo        = CerfHalGetDriverInfo;

    lpddhi->ddCaps.dwSize        = sizeof(DDCAPS);
    lpddhi->ddCaps.dwVidMemTotal = vidSize;
    lpddhi->ddCaps.dwVidMemFree  = vidFree;
    lpddhi->ddCaps.dwVidMemStride = 0;
    lpddhi->ddCaps.ddsCaps.dwCaps =
        DDSCAPS_PRIMARYSURFACE | DDSCAPS_FRONTBUFFER | DDSCAPS_BACKBUFFER |
        DDSCAPS_FLIP | DDSCAPS_SYSTEMMEMORY | DDSCAPS_VIDEOMEMORY;
    lpddhi->ddCaps.dwNumFourCCCodes = 0;
    lpddhi->ddCaps.dwPalCaps     = 0;
    lpddhi->ddCaps.dwBltCaps     = DDBLTCAPS_READSYSMEM | DDBLTCAPS_WRITESYSMEM;
    SETROPBIT(lpddhi->ddCaps.dwRops, SRCCOPY);
    SETROPBIT(lpddhi->ddCaps.dwRops, PATCOPY);
    SETROPBIT(lpddhi->ddCaps.dwRops, BLACKNESS);
    SETROPBIT(lpddhi->ddCaps.dwRops, WHITENESS);
    lpddhi->ddCaps.dwCKeyCaps    = DDCKEYCAPS_SRCBLT;
    lpddhi->ddCaps.dwAlphaCaps   = DDALPHACAPS_ALPHAPIXELS | DDALPHACAPS_ALPHACONSTANT;
    lpddhi->ddCaps.dwMiscCaps    = 0;

    CERF_LOG_X("cerf_guest: buildDDHALInfo dwVidMemTotal", vidSize);
}

/* Software HEL caps (system memory only), copy of the lib's static
   FillHelCaps (ddhinit.cpp:15) which cerf_guest can't link (it's static). */
static void CerfFillHelCaps(DDCAPS* pDDCaps) {
    memset(pDDCaps, 0, sizeof(DDCAPS));
    pDDCaps->dwSize = sizeof(DDCAPS);
    pDDCaps->ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE | DDSCAPS_SYSTEMMEMORY;
    pDDCaps->dwBltCaps   = DDBLTCAPS_READSYSMEM | DDBLTCAPS_WRITESYSMEM;
    pDDCaps->dwCKeyCaps  = DDCKEYCAPS_SRCBLT;
    pDDCaps->dwAlphaCaps = DDALPHACAPS_ALPHAPIXELS | DDALPHACAPS_ALPHACONSTANT |
                           DDALPHACAPS_NONPREMULT;
    SETROPBIT(pDDCaps->dwRops, SRCCOPY);
    SETROPBIT(pDDCaps->dwRops, PATCOPY);
    SETROPBIT(pDDCaps->dwRops, BLACKNESS);
    SETROPBIT(pDDCaps->dwRops, WHITENESS);
}

/* Version-gate the fill: below CE6 the DDHALINFO/DDCAPS layout differs from what
   this fills (CE5 has extra surface callbacks), so filling it into a pre-CE6
   caller corrupts the struct — decline instead. CE6 DDI_DRIVER_VERSION =
   0x00040001 (main.cpp:279). */
EXTERN_C BOOL WINAPI HALInit(LPDDHALINFO lpddhi, BOOL unused1, DWORD modeidx) {
    CERF_LOG_X("cerf_guest: HALInit g_EngineVersion", g_EngineVersion);
    if (g_EngineVersion < 0x00040001u) {
        CERF_LOG("cerf_guest: HALInit declining (pre-CE6) -> software HEL");
        return FALSE;
    }
    buildDDHALInfo(lpddhi, modeidx);
    CerfFillHelCaps(&lpddhi->ddHelCaps);
    CERF_LOG("cerf_guest: HALInit done");
    return TRUE;
}
