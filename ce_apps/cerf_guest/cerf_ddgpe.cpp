#include "cerf_ddgpe.h"
#include "cerf_cursor.h"
#include "cerf_power.h"
#include "main.h"

#ifndef QUERYESCSUPPORT
#define QUERYESCSUPPORT 8
#endif
#ifndef DRVESC_SETSCREENROTATION
#define DRVESC_SETSCREENROTATION 6301
#endif
#ifndef DRVESC_GETSCREENROTATION
#define DRVESC_GETSCREENROTATION 6302
#endif
#ifndef DMDO_0
#define DMDO_0   0
#endif
#ifndef DMDO_90
#define DMDO_90  1
#endif
#ifndef DMDO_180
#define DMDO_180 2
#endif
#ifndef DMDO_270
#define DMDO_270 4
#endif
#ifndef DISP_CHANGE_SUCCESSFUL
#define DISP_CHANGE_SUCCESSFUL 0
#endif

extern "C" int APIENTRY MulDiv(int a, int b, int c) {
    if (c == 0) return -1;
    __int64 prod = (__int64)a * (__int64)b;
    if (c < 0) { prod = -prod; c = -c; }
    prod += (prod >= 0) ? (c / 2) : -(c / 2);
    return (int)(prod / c);
}

static ULONG s_CerfRgbMasks_32bpp[3] = { 0x00FF0000u, 0x0000FF00u, 0x000000FFu };
static ULONG s_CerfRgbMasks_16bpp[3] = { 0xF800u,     0x07E0u,     0x001Fu     };

CerfDDGPE::CerfDDGPE() : DDGPE() {
    m_paletteEntries = 0;
    memset(m_palette, 0, sizeof(m_palette));
    memset(&m_gpeMode, 0, sizeof(m_gpeMode));
    m_pVidHeap   = NULL;
    m_fbRegionVa = NULL;
    m_vidBaseVa  = NULL;
    m_vidSize    = 0;
    m_vidBacking = kCerfVidHeapByPa;
    m_currentRotation = 0;
}

SCODE CerfDDGPE::BltComplete(GPEBltParms* p) {
    (void)p;
    return S_OK;
}

SCODE CerfDDGPE::Line(GPELineParms* pLineParms, EGPEPhase phase) {
    if (phase == gpeSingle || phase == gpePrepare) {
        pLineParms->pLine = (SCODE (GPE::*)(GPELineParms*))&CerfDDGPE::HostLine;
    }
    return S_OK;
}

void CerfDDGPE::SetVisibleSurface(GPESurf* pSurf, BOOL bWaitForVBlank) {
    (void)bWaitForVBlank;
    DDGPESurf* primary = DDGPEPrimarySurface();
    DDGPESurf* target  = (DDGPESurf*)pSurf;
    if (!primary || !target || target == primary) return;
    RECT r;
    r.left = 0; r.top = 0;
    r.right  = primary->Width();
    r.bottom = primary->Height();
    BltExpanded(primary, target, NULL, &r, &r, 0u, 0u, 0xCCCCu);
}

SCODE CerfDDGPE::SetPointerShape(GPESurf* pMask, GPESurf*, int xHot, int yHot,
                                 int cx, int cy) {
    if (pMask) CerfPublishCursor(pMask->Buffer(), pMask->Stride(),
                                 cx, cy, xHot, yHot, TRUE);
    else       CerfPublishCursor(NULL, 0, 0, 0, 0, 0, FALSE);
    return S_OK;
}

SCODE CerfDDGPE::MovePointer(int, int) { return S_OK; }

SCODE CerfDDGPE::SetPalette(const PALETTEENTRY* src, unsigned short firstEntry,
                            unsigned short numEntries) {
    CERF_LOG_X_DEV("cerf_guest: GPE::SetPalette numEntries", (DWORD)numEntries);
    if (src && firstEntry + numEntries <= 256) {
        ULONG rgb[256];
        for (unsigned short i = 0; i < numEntries; ++i) {
            m_palette[firstEntry + i] = src[i];
            rgb[i] = ((ULONG)src[i].peRed << 16) | ((ULONG)src[i].peGreen << 8)
                   | (ULONG)src[i].peBlue;
        }
        if (firstEntry + numEntries > m_paletteEntries) {
            m_paletteEntries = firstEntry + numEntries;
        }
        CerfPublishPalette(rgb, firstEntry, numEntries);
    }
    return S_OK;
}

SCODE CerfDDGPE::GetPalette(PALETTEENTRY** ppPalette, unsigned short* pcEntries) {
    CERF_LOG_X_DEV("cerf_guest: GPE::GetPalette entries", (DWORD)m_paletteEntries);
    if (ppPalette) *ppPalette = (m_paletteEntries > 0) ? m_palette : NULL;
    if (pcEntries) *pcEntries = m_paletteEntries;
    return S_OK;
}

SCODE CerfDDGPE::GetModeInfo(GPEMode* pMode, int modeNo) {
    CERF_LOG_X_DEV("cerf_guest: GPE::GetModeInfo modeNo", (DWORD)modeNo);
    if (modeNo != 0 || pMode == NULL) return E_FAIL;
    pMode->modeId    = 0;
    pMode->width     = (int)g_FbWidth;
    pMode->height    = (int)g_FbHeight;
    pMode->Bpp       = (int)g_FbBpp;
    pMode->frequency = (int)g_FbRefreshRate;
    pMode->format    = (g_FbBpp == 16) ? gpe16Bpp
                     : (g_FbBpp == 24) ? gpe24Bpp
                     : (g_FbBpp == 32) ? gpe32Bpp : gpe8Bpp;
    return S_OK;
}

int CerfDDGPE::NumModes() {
    CERF_LOG_DEV("cerf_guest: GPE::NumModes");
    return 1;
}

int CerfDDGPE::InVBlank() {
    CERF_LOG_DEV("cerf_guest: GPE::InVBlank");
    return 0;
}

ULONG CerfDDGPE::GetGraphicsCaps() {
    CERF_LOG_DEV("cerf_guest: GPE::GetGraphicsCaps");
    return 0;
}

ULONG CerfDDGPE::DrvEscape(SURFOBJ* pso, ULONG iEsc, ULONG cjIn, PVOID pvIn,
                           ULONG cjOut, PVOID pvOut) {
    ULONG pwrRet;
    if (CerfPowerEscape(iEsc, cjOut, pvOut, &pwrRet)) return pwrRet;
    if (iEsc == QUERYESCSUPPORT) {
        DWORD code = (pvIn && cjIn >= sizeof(DWORD)) ? *(DWORD*)pvIn : 0;
        if (code == DRVESC_GETSCREENROTATION || code == DRVESC_SETSCREENROTATION) {
            CERF_LOG_X_DEV("cerf_guest: DrvEscape QUERYESCSUPPORT rot", code);
            return 1;
        }
        if (CerfIsPowerIoctl(code)) return 1;
        return GPE::DrvEscape(pso, iEsc, cjIn, pvIn, cjOut, pvOut);
    }
    if (iEsc == DRVESC_GETSCREENROTATION) {

        if (pvOut)
            *(int*)pvOut = ((DMDO_0 | DMDO_90 | DMDO_180 | DMDO_270) << 8)
                         | (m_currentRotation & 0xFF);
        CERF_LOG_X_DEV("cerf_guest: DrvEscape GETSCREENROTATION cjOut", (DWORD)cjOut);
        return DISP_CHANGE_SUCCESSFUL;
    }
    if (iEsc == DRVESC_SETSCREENROTATION) {

        m_currentRotation = (int)cjIn;

        if (m_pPrimarySurface == NULL ||
            m_pPrimarySurface->Width()  != (int)g_FbWidth ||
            m_pPrimarySurface->Height() != (int)g_FbHeight)
            ApplyFbMode();
        CERF_LOG_X_DEV("cerf_guest: DrvEscape SETSCREENROTATION orient", (DWORD)cjIn);
        return DISP_CHANGE_SUCCESSFUL;
    }
    DWORD firstIn = (pvIn && cjIn >= sizeof(ULONG)) ? *(DWORD*)pvIn : 0xFFFFFFFFu;
    ULONG r = GPE::DrvEscape(pso, iEsc, cjIn, pvIn, cjOut, pvOut);
    CERF_LOG_X_DEV("cerf_guest: DrvEscape iEsc", (DWORD)iEsc);
    CERF_LOG_X_DEV("cerf_guest: DrvEscape firstIn", firstIn);
    CERF_LOG_X_DEV("cerf_guest: DrvEscape ret", (DWORD)r);
    return r;
}

BOOL CerfDDGPE::IsPaletteSettable() {
    CERF_LOG_DEV("cerf_guest: GPE::IsPaletteSettable");
    return FALSE;
}

static ULONG CerfReadGpeDpi(const wchar_t* value_name) {
    HKEY hk;
    ULONG dpi = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Drivers\\Display\\GPE", 0, 0, &hk)
        == ERROR_SUCCESS) {
        DWORD type = 0, data = 0, sz = sizeof(data);
        if (RegQueryValueExW(hk, value_name, NULL, &type, (LPBYTE)&data, &sz)
                == ERROR_SUCCESS && type == REG_DWORD)
            dpi = data;
        RegCloseKey(hk);
    }
    return dpi;
}

BOOL CerfDDGPE::GetScreenDimensions(GPEScreenProps* pProps) {
    CERF_LOG_DEV("cerf_guest: GPE::GetScreenDimensions");
    if (!pProps) return FALSE;

    ULONG dpiX = g_FbDpi ? g_FbDpi : CerfReadGpeDpi(L"LogicalPixelsX");
    ULONG dpiY = g_FbDpi ? g_FbDpi : CerfReadGpeDpi(L"LogicalPixelsY");
    if (!dpiX) dpiX = 96;
    if (!dpiY) dpiY = 96;
    pProps->ulHorzSize   = (g_FbWidth  * 254) / dpiX / 10;
    pProps->ulVertSize   = (g_FbHeight * 254) / dpiY / 10;
    pProps->ulLogPixelsX = dpiX;
    pProps->ulLogPixelsY = dpiY;
    pProps->ulAspectX    = 36;
    pProps->ulAspectY    = 36;
    pProps->ulAspectXY   = 51;
    return TRUE;
}

ULONG* CerfDDGPE::GetClearTypeRGBMasks() {
    CERF_LOG_DEV("cerf_guest: GPE::GetClearTypeRGBMasks");
    return (g_FbBpp == 16) ? s_CerfRgbMasks_16bpp
         : (g_FbBpp == 32) ? s_CerfRgbMasks_32bpp : NULL;
}

extern "C" GPE* GetGPE() {
    static CerfDDGPE* s_instance = NULL;
    if (!s_instance) s_instance = new CerfDDGPE();
    return s_instance;
}
