#include <windows.h>
#include <winddi.h>

#include "include/cerf_gpe.h"
#include "include/cerf_ddi.h"
#include "cerf_ddgpe.h"
#include "cerf_eng_callbacks.h"

ULONG CerfSwapRedBlue(ULONG value) {
    ULONG out = value;
    ((BYTE*)&out)[0] = ((BYTE*)&value)[2];
    ((BYTE*)&out)[2] = ((BYTE*)&value)[0];
    return out;
}

static ULONG CerfRGBError(ULONG v1, ULONG v2) {
    BYTE* p1 = (BYTE*)&v1;
    BYTE* p2 = (BYTE*)&v2;
    long accum = (long)p1[0] - (long)p2[0];
    accum *= accum;
    long diff = (long)p1[1] - (long)p2[1];
    accum += diff * diff;
    diff = (long)p1[2] - (long)p2[2];
    return (ULONG)(accum + diff * diff);
}

extern "C" ULONG APIENTRY DrvRealizeColor(USHORT iDstType, ULONG cEntries,
                                          ULONG* pPalette, ULONG rgbColor) {
    ULONG dstValue = 0;

    switch (iDstType) {
    case PAL_INDEXED: {
        if (!pPalette) return 0;
        ULONG  smallest = 0x7FFFFFFFu;
        ULONG* pal      = pPalette;
        for (ULONG i = 0; i < cEntries; ++i) {
            const ULONG error = CerfRGBError(rgbColor, *pal++);
            if (error > smallest) continue;
            smallest = error;
            dstValue = i;
            if (error == 0) break;
        }
        return dstValue;
    }
    case PAL_BITFIELDS: {
        if (!pPalette) return 0;
        if (pPalette[0] == 0xF800u && pPalette[1] == 0x07E0u && pPalette[2] == 0x001Fu) {
            dstValue  = ((rgbColor << 24) >> 16) & pPalette[0];
            dstValue |= ((rgbColor << 16) >> 21) & pPalette[1];
            dstValue |= ((rgbColor <<  8) >> 27) & pPalette[2];
            return dstValue;
        }
        ULONG* pal = pPalette;
        ULONG  n   = cEntries;
        for (int shift_left = 24; shift_left >= 0 && n; shift_left -= 8, --n) {
            ULONG mask = *pal;
            int shift_right = 32;
            while (mask) { mask >>= 1; --shift_right; }
            dstValue |= ((rgbColor << shift_left) >> shift_right) & *pal++;
        }
        return dstValue;
    }
    case PAL_BGR:
        return CerfSwapRedBlue(rgbColor);
    case PAL_RGB:
        return rgbColor;
    }
    return 0;
}

extern "C" ULONG APIENTRY DrvUnrealizeColor(USHORT iSrcType, ULONG cEntries,
                                            ULONG* pPalette, ULONG iRealizedColor) {
    ULONG dst_masks[3] = { 0x000000FFu, 0x0000FF00u, 0x00FF0000u };
    ULONG dstValue = 0;

    switch (iSrcType) {
    case PAL_INDEXED:
        if (!pPalette || iRealizedColor >= cEntries) return 0;
        return pPalette[iRealizedColor];

    case PAL_BITFIELDS: {
        if (!pPalette) return 0;
        ULONG* pal      = pPalette;
        ULONG* dst_mask = dst_masks;
        ULONG  n        = cEntries;
        for (int shift_right = 24; shift_right >= 0 && n; shift_right -= 8, --n) {
            ULONG mask = *pal;
            int   bits = 0;
            int   shift_left = 32;
            while (mask) {
                if (mask & 1u) ++bits;
                mask >>= 1;
                --shift_left;
            }
            ULONG color = (iRealizedColor & *pal++) << shift_left;
            if (bits) color |= color >> bits;
            dstValue |= (color >> shift_right) & *dst_mask++;
        }
        return dstValue;
    }
    case PAL_BGR:
        return CerfSwapRedBlue(iRealizedColor);
    case PAL_RGB:
        return iRealizedColor;
    }
    return 0;
}

extern "C" BOOL APIENTRY DrvSetPalette(DHPDEV dhpdev, PALOBJ* ppalo, FLONG,
                                       ULONG iStart, ULONG cColors) {
    GPE* pGPE = (GPE*)dhpdev;
    if (!pGPE || cColors > 256) return FALSE;

    ULONG colors[256];
    cColors = PALOBJ_cGetColors(ppalo, iStart, cColors, colors);
    if (!cColors) return FALSE;

    if (FAILED(pGPE->SetPalette((const PALETTEENTRY*)colors,
                                (unsigned short)iStart,
                                (unsigned short)cColors))) {
        return FALSE;
    }
    return TRUE;
}

extern "C" ULONG APIENTRY DrvSetPointerShape(SURFOBJ*, SURFOBJ* psoMask,
                                             SURFOBJ* psoColor, XLATEOBJ*,
                                             LONG xHot, LONG yHot, LONG x, LONG y,
                                             RECTL*, FLONG) {
    GPE* pGPE = GetGPE();
    if (!pGPE) return SPS_ERROR;

    GPESurf mask_surf;
    GPESurf color_surf;
    GPESurf* pMask  = NULL;
    GPESurf* pColor = NULL;

    if (psoMask) {
        if (psoMask->dhsurf) {
            pMask = (GPESurf*)psoMask->dhsurf;
        } else {
            mask_surf.Init((int)psoMask->sizlBitmap.cx, (int)psoMask->sizlBitmap.cy,
                           psoMask->pvScan0, (int)psoMask->lDelta,
                           CerfIFormatToEGPE(psoMask->iBitmapFormat));
            pMask = &mask_surf;
        }
    }
    if (psoColor) {
        if (psoColor->dhsurf) {
            pColor = (GPESurf*)psoColor->dhsurf;
        } else {
            color_surf.Init((int)psoColor->sizlBitmap.cx, (int)psoColor->sizlBitmap.cy,
                            psoColor->pvScan0, (int)psoColor->lDelta,
                            CerfIFormatToEGPE(psoColor->iBitmapFormat));
            pColor = &color_surf;
        }
    }

    const int cx = psoMask ? (int)psoMask->sizlBitmap.cx : 0;
    const int cy = psoMask ? (int)(psoMask->sizlBitmap.cy >> 1) : 0;

    if (FAILED(pGPE->SetPointerShape(pMask, pColor, (int)xHot, (int)yHot, cx, cy))) {
        return SPS_ERROR;
    }
    if (((x > 0) && (y > 0)) || (x == -1) || (y == -1)) {
        pGPE->MovePointer((int)x, (int)y);
    }
    return SPS_ACCEPT_NOEXCLUDE;
}

extern "C" VOID APIENTRY DrvMovePointer(SURFOBJ*, LONG x, LONG y, RECTL*) {
    GPE* pGPE = GetGPE();
    if (pGPE) pGPE->MovePointer((int)x, (int)y);
}

extern "C" ULONG APIENTRY DrvEscape(DHPDEV dhpdev, SURFOBJ* pso, ULONG iEsc,
                                    ULONG cjIn, PVOID pvIn, ULONG cjOut, PVOID pvOut) {
    GPE* pGPE = (GPE*)dhpdev;
    if (!pGPE) pGPE = GetGPE();
    if (!pGPE) return 0;
    return pGPE->DrvEscape(pso, iEsc, cjIn, pvIn, cjOut, pvOut);
}

extern "C" BOOL APIENTRY DrvContrastControl(DHPDEV, ULONG, ULONG*) {
    return FALSE;
}

extern "C" VOID APIENTRY DrvPowerHandler(DHPDEV, BOOL) {
}
