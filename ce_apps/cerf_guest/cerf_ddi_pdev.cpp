#include <windows.h>
#include <winddi.h>

#include "include/cerf_gpe.h"
#include "include/cerf_ddi.h"
#include "cerf_ddgpe.h"
#include "cerf_eng_callbacks.h"
#include "main.h"

#define CERF_DDI_VERSION_CE3   0x00020001u
#define CERF_DEVMODEW_SIZE_CE3 188u
#define CERF_DEVMODEW_SIZE_CE4 192u

typedef char CerfDevModeW_size_check[(sizeof(DEVMODEW) == CERF_DEVMODEW_SIZE_CE4) ? 1 : -1];

#define CERF_DT_RASDISPLAY 1u
#define CERF_RC_BITBLT     0x0001u
#define CERF_RC_PALETTE    0x0100u
#define CERF_RC_STRETCHBLT 0x0800u
#define CERF_RC_STRETCHDIB 0x2000u

#define CERF_DEFAULT_HORZ_SIZE_MM 64u
#define CERF_DEFAULT_VERT_SIZE_MM 60u
#define CERF_DEFAULT_LOG_PIXELS   96u

extern "C" ULONG APIENTRY DrvGetModes(HANDLE, ULONG cjSize, DEVMODEW* pdm) {
    GPE* pGPE = GetGPE();
    if (!pGPE) return 0;

    const int   num_modes = pGPE->NumModes();
    const ULONG dm_size   = (g_EngineVersion == CERF_DDI_VERSION_CE3)
                                ? CERF_DEVMODEW_SIZE_CE3 : CERF_DEVMODEW_SIZE_CE4;
    const ULONG entry     = dm_size + sizeof(GPEMode);
    const ULONG needed    = (ULONG)num_modes * entry;

    if (!pdm) return needed;
    if (cjSize != needed) return 0;

    memset(pdm, 0, cjSize);
    BYTE* out = (BYTE*)pdm;

    for (int i = 0; i < num_modes; ++i, out += entry) {
        GPEMode mode;
        memset(&mode, 0, sizeof(mode));
        if (FAILED(pGPE->GetModeInfo(&mode, i))) return 0;

        DEVMODEW dmw;
        memset(&dmw, 0, sizeof(dmw));
        memcpy(dmw.dmDeviceName, L"GPE", 8);
        dmw.dmSize             = (WORD)dm_size;
        dmw.dmDriverExtra      = (WORD)sizeof(GPEMode);
        dmw.dmFields           = DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT |
                                 DM_DISPLAYFREQUENCY | DM_DISPLAYFLAGS;
        dmw.dmBitsPerPel       = (DWORD)mode.Bpp;
        dmw.dmPelsWidth        = (DWORD)mode.width;
        dmw.dmPelsHeight       = (DWORD)mode.height;
        dmw.dmDisplayFrequency = (DWORD)mode.frequency;

        memcpy(out, &dmw, dm_size);
        memcpy(out + dm_size, &mode, sizeof(mode));
    }
    return cjSize;
}

static void CerfWriteCap(ULONG* caps, ULONG cj, ULONG index, ULONG value) {
    if ((index + 1u) * sizeof(ULONG) <= cj) caps[index] = value;
}

extern "C" DHPDEV APIENTRY DrvEnablePDEV(DEVMODEW* pdm, LPWSTR, ULONG, HSURF*,
                                         ULONG cjCaps, ULONG* pdevcaps,
                                         ULONG cjDevInfo, DEVINFO* pdi,
                                         HDEV, LPWSTR, HANDLE) {
    CerfReadFbRegs();
    GPE* pGPE = GetGPE();
    if (!pGPE || !pdm || !pdevcaps) return NULL;

    if (pdm->dmDriverExtra == sizeof(GPEMode) && pdi) {
        const GPEMode* mode = (const GPEMode*)((const BYTE*)pdm + pdm->dmSize);
        if (FAILED(pGPE->SetMode(mode->modeId, &pdi->hpalDefault))) {
            CERF_LOG("cerf_guest: DrvEnablePDEV SetMode failed");
            return NULL;
        }
    }

    GPEScreenProps props;
    if (!pGPE->GetScreenDimensions(&props)) {
        props.ulHorzSize   = CERF_DEFAULT_HORZ_SIZE_MM;
        props.ulVertSize   = CERF_DEFAULT_VERT_SIZE_MM;
        props.ulLogPixelsX = g_FbDpi ? g_FbDpi : CERF_DEFAULT_LOG_PIXELS;
        props.ulLogPixelsY = g_FbDpi ? g_FbDpi : CERF_DEFAULT_LOG_PIXELS;
        props.ulAspectX    = 1;
        props.ulAspectY    = 1;
        props.ulAspectXY   = 1;
    }

    const BOOL  is_ce3 = (g_EngineVersion == CERF_DDI_VERSION_CE3);
    const ULONG bpp    = pdm->dmBitsPerPel;

    ULONG raster = CERF_RC_BITBLT | CERF_RC_STRETCHBLT;
    if (!is_ce3) raster |= CERF_RC_STRETCHDIB;
    if (pGPE->IsPaletteSettable()) raster |= CERF_RC_PALETTE;

    ULONG text_caps = 0;
    if (bpp > 8) text_caps |= GCAPS_GRAY16;
    if (bpp > 8) text_caps |= GCAPS_CLEARTYPE;

    const ULONG graphics_caps = pGPE->GetGraphicsCaps() | text_caps;
    const ULONG gdi_text_caps = graphics_caps & GCAPS_TEXT_CAPS;

    CerfWriteCap(pdevcaps, cjCaps,  0, g_EngineVersion);
    CerfWriteCap(pdevcaps, cjCaps,  1, CERF_DT_RASDISPLAY);
    CerfWriteCap(pdevcaps, cjCaps,  2, props.ulHorzSize);
    CerfWriteCap(pdevcaps, cjCaps,  3, props.ulVertSize);
    CerfWriteCap(pdevcaps, cjCaps,  4, g_FbWidth);
    CerfWriteCap(pdevcaps, cjCaps,  5, g_FbHeight);
    CerfWriteCap(pdevcaps, cjCaps,  6, bpp);
    CerfWriteCap(pdevcaps, cjCaps,  7, 1u);
    CerfWriteCap(pdevcaps, cjCaps,  8, (ULONG)(((ULONGLONG)1) << bpp));
    CerfWriteCap(pdevcaps, cjCaps,  9, raster);
    CerfWriteCap(pdevcaps, cjCaps, 10, props.ulLogPixelsX);
    CerfWriteCap(pdevcaps, cjCaps, 11, props.ulLogPixelsY);
    CerfWriteCap(pdevcaps, cjCaps, 12, gdi_text_caps);

    if (is_ce3) {
        CerfWriteCap(pdevcaps, cjCaps, 13, 0u);
        CerfWriteCap(pdevcaps, cjCaps, 14, 0u);
        CerfWriteCap(pdevcaps, cjCaps, 15, 0u);
        CerfWriteCap(pdevcaps, cjCaps, 16, props.ulAspectX);
        CerfWriteCap(pdevcaps, cjCaps, 17, props.ulAspectY);
        CerfWriteCap(pdevcaps, cjCaps, 18, props.ulAspectXY);
        CerfWriteCap(pdevcaps, cjCaps, 19, 0u);
    } else {
        CerfWriteCap(pdevcaps, cjCaps, 13, 0u);
        CerfWriteCap(pdevcaps, cjCaps, 14, 0u);
        CerfWriteCap(pdevcaps, cjCaps, 15, 0u);
        CerfWriteCap(pdevcaps, cjCaps, 16, 0u);
        CerfWriteCap(pdevcaps, cjCaps, 17, props.ulAspectX);
        CerfWriteCap(pdevcaps, cjCaps, 18, props.ulAspectY);
        CerfWriteCap(pdevcaps, cjCaps, 19, props.ulAspectXY);
    }

    if (pdi && cjDevInfo >= sizeof(DEVINFO)) {
        pdi->flGraphicsCaps = graphics_caps;
    }
    return (DHPDEV)pGPE;
}

extern "C" VOID APIENTRY DrvDisablePDEV(DHPDEV dhpdev) {
    GPE* pGPE = (GPE*)dhpdev;
    if (pGPE) pGPE->SetHSurf(0);
}

extern "C" HSURF APIENTRY DrvEnableSurface(DHPDEV dhpdev) {
    GPE* pGPE = (GPE*)dhpdev;
    if (!pGPE) return NULL;
    GPESurf* primary = pGPE->PrimarySurface();
    if (!primary) {
        CERF_LOG("cerf_guest: DrvEnableSurface with no primary surface");
        return NULL;
    }
    SIZEL sizl;
    sizl.cx = pGPE->ScreenWidth();
    sizl.cy = pGPE->ScreenHeight();

    HSURF hsurf = EngCreateDeviceSurface((DHSURF)primary, sizl,
                                         CerfEGPEToIFormat(primary->Format()));
    pGPE->SetHSurf((ULONG)(ULONG_PTR)hsurf);
    return hsurf;
}

extern "C" VOID APIENTRY DrvDisableSurface(DHPDEV dhpdev) {
    GPE* pGPE = (GPE*)dhpdev;
    if (!pGPE) return;
    EngDeleteSurface((HSURF)(ULONG_PTR)pGPE->GetHSurf());
    pGPE->SetHSurf(0);
}

extern "C" HBITMAP APIENTRY DrvCreateDeviceBitmap(DHPDEV dhpdev, SIZEL sizl, ULONG iFormat) {
    GPE* pGPE = (GPE*)dhpdev;
    if (!pGPE || iFormat > 9) return (HBITMAP)0xFFFFFFFF;

    GPESurf* surf = NULL;
    if (FAILED(pGPE->AllocSurface(&surf, sizl.cx, sizl.cy,
                                  CerfIFormatToEGPE(iFormat),
                                  GPE_PREFER_VIDEO_MEMORY))) {
        return (HBITMAP)0xFFFFFFFF;
    }
    HBITMAP bitmap = EngCreateDeviceBitmap((DHSURF)surf, sizl, iFormat);
    if (!bitmap) {
        delete surf;
        return (HBITMAP)0xFFFFFFFF;
    }
    surf->m_nHandle = (ULONG)(ULONG_PTR)bitmap;
    return bitmap;
}

extern "C" VOID APIENTRY DrvDeleteDeviceBitmap(DHSURF dhsurf) {
    GPESurf* surf = (GPESurf*)dhsurf;
    if (!surf) return;
    EngDeleteSurface((HSURF)(ULONG_PTR)surf->m_nHandle);
    delete surf;
}

extern "C" VOID APIENTRY DrvDisableDriver(void) {
}
