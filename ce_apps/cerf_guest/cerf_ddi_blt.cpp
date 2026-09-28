#include <windows.h>
#include <winddi.h>

#include "include/cerf_gpe.h"
#include "include/cerf_ddi.h"
#include "include/cerf_surfobj.h"
#include "cerf_ddgpe.h"
#include "cerf_eng_callbacks.h"

const BYTE kCerfMixToRop3[17] = {
    0xFF, 0x00, 0x05, 0x0A, 0x0F, 0x50, 0x55, 0x5A,
    0x5F, 0xA0, 0xA5, 0xAA, 0xAF, 0xF0, 0xF5, 0xFA, 0xFF
};

static ULONG g_RGBPalette[4] = { 0x000000FFu, 0x0000FF00u, 0x00FF0000u, 0xFF000000u };
static ULONG g_BGRPalette[4] = { 0x00FF0000u, 0x0000FF00u, 0x000000FFu, 0xFF000000u };

static BOOL CerfSourceMatters(ROP4 r) { return ((r ^ (r >> 2)) & 0x3333u) != 0u; }
static BOOL CerfBrushMatters(ROP4 r)  { return ((r ^ (r >> 4)) & 0x0F0Fu) != 0u; }
static BOOL CerfMaskMatters(ROP4 r)   { return ((r ^ (r >> 8)) & 0x00FFu) != 0u; }

static void CerfSetSurfaceFormat(GPESurf* surf, XLATEOBJ* pxlo, ULONG iPal) {
    if (!surf || !pxlo) return;
    GPEFormat* fmt = surf->FormatPtr();
    if (fmt->m_pPalette) return;

    USHORT pal_type = (iPal == XO_SRCPALETTE) ? pxlo->iSrcType : pxlo->iDstType;

    if (pal_type == PAL_BGR) {
        fmt->m_PaletteEntries = (surf->Format() == gpe32Bpp) ? 4 : 3;
        fmt->m_pPalette       = g_BGRPalette;
        fmt->m_OwnsPalette    = FALSE;
        return;
    }
    if (pal_type == PAL_RGB) {
        fmt->m_PaletteEntries = (surf->Format() == gpe32Bpp) ? 4 : 3;
        fmt->m_pPalette       = g_RGBPalette;
        fmt->m_OwnsPalette    = FALSE;
        return;
    }

    ULONG count = XLATEOBJ_cGetPalette(pxlo, iPal, 0, NULL);
    if (count == 0) return;
    ULONG* palette = new ULONG[count];
    if (!palette) return;
    count = XLATEOBJ_cGetPalette(pxlo, iPal, count, palette);
    fmt->m_pPalette       = palette;
    fmt->m_PaletteEntries = (int)count;
    fmt->m_OwnsPalette    = TRUE;
}

static ULONG* CerfBuildIndexedLookup(XLATEOBJ* pxlo) {
    ULONG src_count = XLATEOBJ_cGetPalette(pxlo, XO_SRCPALETTE, 0, NULL);
    if (src_count == 0) return NULL;
    if (src_count > 256) src_count = 256;

    ULONG* lut = new ULONG[256];
    if (!lut) return NULL;
    for (ULONG z = 0; z < 256; ++z) lut[z] = 0;
    XLATEOBJ_cGetPalette(pxlo, XO_SRCPALETTE, src_count, lut);

    if (pxlo->iDstType == PAL_INDEXED) {
        ULONG dst_palette[256];
        ULONG dst_count = XLATEOBJ_cGetPalette(pxlo, XO_DESTPALETTE, 0, NULL);
        if (dst_count > 256) dst_count = 256;
        if (dst_count) {
            XLATEOBJ_cGetPalette(pxlo, XO_DESTPALETTE, dst_count, dst_palette);
            for (ULONG i = 0; i < src_count; ++i) {
                lut[i] = DrvRealizeColor(PAL_INDEXED, dst_count, dst_palette, lut[i]);
            }
        }
        return lut;
    }

    if (pxlo->iDstType == PAL_BITFIELDS) {
        ULONG masks[3];
        XLATEOBJ_cGetPalette(pxlo, XO_DESTPALETTE, 3, masks);
        for (ULONG i = 0; i < src_count; ++i) {
            lut[i] = DrvRealizeColor(PAL_BITFIELDS, 3, masks, lut[i]);
        }
        return lut;
    }

    if (pxlo->iDstType == PAL_BGR) {
        for (ULONG i = 0; i < src_count; ++i) {
            lut[i] = CerfSwapRedBlue(lut[i]);
        }
    }
    return lut;
}

static ULONG* CerfBuildMonoLookup(XLATEOBJ* pxlo) {
    if (pxlo->iSrcType != PAL_INDEXED || !pxlo->pulXlate) return NULL;
    ULONG* lut = new ULONG[256];
    if (!lut) return NULL;
    const ULONG background = pxlo->pulXlate[0];
    for (ULONG i = 0; i < 256; ++i) lut[i] = (i == background) ? 1u : 0u;
    return lut;
}

static ColorConverter g_Converter;

static BOOL CerfDecodeXlate(XLATEOBJ* pxlo, GPEBltParms* parms, BOOL* lookup_owned) {
    if (pxlo->iSrcType == PAL_FOURCC || pxlo->iDstType == PAL_FOURCC) {
        CERF_LOG("cerf_guest: UNIMPLEMENTED PAL_FOURCC colour conversion");
        return FALSE;
    }
    if (pxlo->flXlate == XO_TRIVIAL) {
        parms->pLookup = NULL;
        return TRUE;
    }
    if (pxlo->flXlate == XO_TABLE) {
        parms->pLookup = pxlo->pulXlate;
        return TRUE;
    }
    if (pxlo->flXlate == XO_TO_MONO) {
        if (!pxlo->pulXlate) {
            CERF_LOG("cerf_guest: UNIMPLEMENTED XO_TO_MONO with no pulXlate");
            return FALSE;
        }
        if (pxlo->iSrcType == PAL_INDEXED) {
            parms->pLookup = CerfBuildMonoLookup(pxlo);
            if (!parms->pLookup) return FALSE;
            *lookup_owned = TRUE;
            return TRUE;
        }
        parms->toMono = 1;
        parms->monoBg = pxlo->pulXlate[0];
        return TRUE;
    }
    if (pxlo->iSrcType == PAL_INDEXED) {
        parms->pLookup = CerfBuildIndexedLookup(pxlo);
        if (!parms->pLookup) {
            CERF_LOG("cerf_guest: DROP PAL_INDEXED src lookup build failed");
            return FALSE;
        }
        *lookup_owned = TRUE;
        return TRUE;
    }
    if (pxlo->iDstType == PAL_INDEXED) {
        CERF_LOG("cerf_guest: UNIMPLEMENTED masked-src to PAL_INDEXED dst");
        return FALSE;
    }
    parms->pConvert        = &ColorConverter::Convert;
    parms->pColorConverter = &g_Converter;
    return TRUE;
}

static void CerfReleaseSurfaceFormat(GPESurf* surf) {
    if (!surf) return;
    GPEFormat* fmt = surf->FormatPtr();
    if (fmt->m_OwnsPalette && fmt->m_pPalette) delete[] fmt->m_pPalette;
    fmt->m_pPalette       = NULL;
    fmt->m_PaletteEntries = 0;
    fmt->m_OwnsPalette    = FALSE;
}

static BOOL CerfBltFail(GPESurf* pDst, GPESurf* pSrc, GPEBltParms* parms,
                        BOOL lookup_owned) {
    if (lookup_owned && parms->pLookup) delete[] parms->pLookup;
    CerfReleaseSurfaceFormat(pDst);
    CerfReleaseSurfaceFormat(pSrc);
    return FALSE;
}

BOOL APIENTRY AnyBlt(SURFOBJ* psoTrg, SURFOBJ* psoSrc, SURFOBJ* psoMask,
                     CLIPOBJ* pco, XLATEOBJ* pxlo, RECTL* prclTrg,
                     RECTL* prclSrc, POINTL* pptlMask, BRUSHOBJ* pbo,
                     POINTL* pptlBrush, ULONG rop4, ULONG bltFlags,
                     int iMode, BLENDFUNCTION blendFunction) {
    GPE* pGPE = GetGPE();
    if (!pGPE || !psoTrg || !prclTrg) return FALSE;

    CerfTmpSurf tDst, tSrc, tMask;
    GPESurf* pDst  = CerfWrapSurfobj(&tDst, psoTrg);
    GPESurf* pSrc  = CerfWrapSurfobj(&tSrc, psoSrc);
    GPESurf* pMask = CerfWrapSurfobj(&tMask, psoMask);
    if (!pDst) return FALSE;

    RECTL rclTrg = *prclTrg;
    if (rclTrg.right < rclTrg.left) {
        const LONG t = rclTrg.right; rclTrg.right = rclTrg.left; rclTrg.left = t;
    }
    if (rclTrg.bottom < rclTrg.top) {
        const LONG t = rclTrg.bottom; rclTrg.bottom = rclTrg.top; rclTrg.top = t;
    }
    prclTrg = &rclTrg;

    RECTL rclSrcN;
    if (prclSrc) {
        rclSrcN = *prclSrc;
        if (rclSrcN.right < rclSrcN.left) {
            const LONG t = rclSrcN.right; rclSrcN.right = rclSrcN.left; rclSrcN.left = t;
        }
        if (rclSrcN.bottom < rclSrcN.top) {
            const LONG t = rclSrcN.bottom; rclSrcN.bottom = rclSrcN.top; rclSrcN.top = t;
        }
        prclSrc = &rclSrcN;
    }

    GPEBltParms parms;
    memset(&parms, 0, sizeof(parms));
    parms.pDst          = pDst;
    parms.prclDst       = prclTrg;
    parms.rop4          = (ROP4)rop4;
    parms.iMode         = iMode;
    parms.blendFunction = blendFunction;
    parms.solidColor    = 0xFFFFFFFFu;
    parms.xPositive     = 1;
    parms.yPositive     = 1;

    RECTL rclMask;
    BOOL  lookup_owned = FALSE;
    if (CerfSourceMatters((ROP4)rop4)) {
        if (!pSrc || !prclSrc) return FALSE;
        parms.pSrc    = pSrc;
        parms.prclSrc = prclSrc;
        if ((prclTrg->right - prclTrg->left) != (prclSrc->right - prclSrc->left) ||
            (prclTrg->bottom - prclTrg->top) != (prclSrc->bottom - prclSrc->top)) {
            bltFlags |= BLT_STRETCH;
        }
        if (pxlo) {
            CerfSetSurfaceFormat(pDst, pxlo, XO_DESTPALETTE);
            CerfSetSurfaceFormat(pSrc, pxlo, XO_SRCPALETTE);

            if (!CerfDecodeXlate(pxlo, &parms, &lookup_owned))
                return CerfBltFail(pDst, pSrc, &parms, lookup_owned);
        }
    } else if (bltFlags & BLT_STRETCH) {
        bltFlags &= ~BLT_STRETCH;
    }
    parms.bltFlags = bltFlags;

    if (CerfBrushMatters((ROP4)rop4)) {
        if (!pbo) {
            CERF_LOG("cerf_guest: DROP brush-matters rop with null BRUSHOBJ");
            return CerfBltFail(pDst, pSrc, &parms, lookup_owned);
        }
        parms.pptlBrush = pptlBrush;
        if (pbo->iSolidColor == 0xFFFFFFFFu) {
            void* rb = pbo->pvRbrush ? pbo->pvRbrush : BRUSHOBJ_pvGetRbrush(pbo);
            if (!rb) {
                CERF_LOG("cerf_guest: DROP pattern brush not realized");
                return CerfBltFail(pDst, pSrc, &parms, lookup_owned);
            }
            parms.pBrush = (GPESurf*)rb;
        } else {
            parms.solidColor = pbo->iSolidColor;
            parms.pptlBrush  = NULL;
        }
    } else if (pbo) {
        parms.solidColor = pbo->iSolidColor;
    }

    if (CerfMaskMatters((ROP4)rop4) && pMask) {
        if (pptlMask) {
            rclMask.left   = pptlMask->x;
            rclMask.top    = pptlMask->y;
            rclMask.right  = pptlMask->x + (prclTrg->right - prclTrg->left);
            rclMask.bottom = pptlMask->y + (prclTrg->bottom - prclTrg->top);
        } else if (prclSrc) {
            rclMask.left   = prclSrc->left;
            rclMask.top    = prclSrc->top;
            rclMask.right  = prclSrc->left + (prclTrg->right - prclTrg->left);
            rclMask.bottom = prclSrc->top  + (prclTrg->bottom - prclTrg->top);
        } else {
            CERF_LOG("cerf_guest: DROP mask-matters rop with no mask rect");
            return CerfBltFail(pDst, pSrc, &parms, lookup_owned);
        }
        parms.pMask    = pMask;
        parms.prclMask = &rclMask;
    }

    SCODE sc = pGPE->BltPrepare(&parms);
    BOOL  ok = !FAILED(sc);

    if (ok) {
        if (!pco || pco->iDComplexity == DC_TRIVIAL) {
            parms.prclClip = NULL;
            sc = (pGPE->*parms.pBlt)(&parms);
            ok = !FAILED(sc);
        } else if (pco->iDComplexity == DC_RECT) {
            parms.prclClip = &pco->rclBounds;
            sc = (pGPE->*parms.pBlt)(&parms);
            ok = !FAILED(sc);
        } else {
            GPESurf* snap = NULL;
            if (((CerfDDGPE*)pGPE)->BltAliasKind(&parms) != kCerfAliasNone &&
                !((CerfDDGPE*)pGPE)->SnapshotSource(&parms, &snap)) {
                pGPE->BltComplete(&parms);
                if (lookup_owned && parms.pLookup) delete[] parms.pLookup;
                CerfReleaseSurfaceFormat(pDst);
                CerfReleaseSurfaceFormat(pSrc);
                return FALSE;
            }
            ENUMRECTS ce;
            int more = 1;
            CLIPOBJ_cEnumStart(pco, FALSE, CT_RECTANGLES, CD_ANY, 0);
            for (ce.c = 0; ce.c || more; ) {
                if (ce.c == 0) {
                    more = CLIPOBJ_bEnum(pco, sizeof(ce), (ULONG*)&ce);
                    if (!ce.c) continue;
                }
                parms.prclClip = &ce.arcl[--ce.c];
                sc = (pGPE->*parms.pBlt)(&parms);
                if (FAILED(sc)) { ok = FALSE; break; }
            }
            if (snap) {
                parms.pSrc    = pSrc;
                parms.prclSrc = prclSrc;
                delete snap;
            }
        }
    }

    pGPE->BltComplete(&parms);

    if (lookup_owned && parms.pLookup) delete[] parms.pLookup;
    CerfReleaseSurfaceFormat(pDst);
    CerfReleaseSurfaceFormat(pSrc);
    return ok;
}

extern "C" BOOL APIENTRY DrvBitBlt(SURFOBJ* psoTrg, SURFOBJ* psoSrc, SURFOBJ* psoMask,
                                   CLIPOBJ* pco, XLATEOBJ* pxlo, RECTL* prclTrg,
                                   POINTL* pptlSrc, POINTL* pptlMask, BRUSHOBJ* pbo,
                                   POINTL* pptlBrush, ROP4 rop4) {
    RECTL rclSrc;
    rclSrc.left = 0; rclSrc.top = 0; rclSrc.right = 0; rclSrc.bottom = 0;
    if (prclTrg) {
        const LONG x = pptlSrc ? pptlSrc->x : 0;
        const LONG y = pptlSrc ? pptlSrc->y : 0;
        rclSrc.left   = x;
        rclSrc.top    = y;
        rclSrc.right  = x + (prclTrg->right - prclTrg->left);
        rclSrc.bottom = y + (prclTrg->bottom - prclTrg->top);
    }
    BLENDFUNCTION bf;
    memset(&bf, 0, sizeof(bf));
    bf.SourceConstantAlpha = 0xFF;
    return AnyBlt(psoTrg, psoSrc, psoMask, pco, pxlo, prclTrg, &rclSrc, pptlMask,
                  pbo, pptlBrush, rop4, 0u, 0, bf);
}

extern "C" BOOL APIENTRY DrvAnyBlt(SURFOBJ* psoTrg, SURFOBJ* psoSrc, SURFOBJ* psoMask,
                                   CLIPOBJ* pco, XLATEOBJ* pxlo, POINTL* pptlHTOrg,
                                   RECTL* prclTrg, RECTL* prclSrc, POINTL* pptlMask,
                                   BRUSHOBJ* pbo, POINTL* pptlBrush, ROP4 rop4,
                                   ULONG iMode, ULONG bltFlags) {
    (void)pptlHTOrg;
    BLENDFUNCTION bf;
    memset(&bf, 0, sizeof(bf));
    bf.SourceConstantAlpha = 0xFF;
    return AnyBlt(psoTrg, psoSrc, psoMask, pco, pxlo, prclTrg, prclSrc, pptlMask,
                  pbo, pptlBrush, rop4, bltFlags, (int)iMode, bf);
}

extern "C" BOOL APIENTRY DrvTransparentBlt(SURFOBJ* psoTrg, SURFOBJ* psoSrc, CLIPOBJ* pco,
                                           XLATEOBJ* pxlo, RECTL* prclTrg, RECTL* prclSrc,
                                           ULONG TransColor) {
    BRUSHOBJ bo;
    BLENDFUNCTION bf;
    memset(&bf, 0, sizeof(bf));
    bf.SourceConstantAlpha = 0xFF;
    bo.iSolidColor = TransColor;
    bo.pvRbrush    = NULL;
    return AnyBlt(psoTrg, psoSrc, NULL, pco, pxlo, prclTrg, prclSrc, NULL,
                  &bo, NULL, 0xCCCCu, BLT_TRANSPARENT, 0, bf);
}

extern "C" BOOL APIENTRY DrvPaint(SURFOBJ* pso, CLIPOBJ* pco, BRUSHOBJ* pbo,
                                  POINTL* pptlBrush, MIX mix) {
    if (!pco) return FALSE;
    const ROP4 rop4 = (ROP4)((((ULONG)kCerfMixToRop3[(mix >> 8) & 0xFu]) << 8) |
                             (ULONG)kCerfMixToRop3[mix & 0xFu]);
    return DrvBitBlt(pso, NULL, NULL, pco, NULL, &pco->rclBounds, NULL, NULL,
                     pbo, pptlBrush, rop4);
}

extern "C" BOOL APIENTRY DrvRealizeBrush(BRUSHOBJ* pbo, SURFOBJ* psoTarget,
                                         SURFOBJ* psoPattern, SURFOBJ* psoMask,
                                         XLATEOBJ* pxlo, ULONG iHatch) {
    (void)psoMask;
    (void)iHatch;
    if (!pbo || !psoTarget || !psoPattern) return FALSE;

    CerfTmpSurf tPat, tTrg;
    GPESurf* pPat = CerfWrapSurfobj(&tPat, psoPattern);
    GPESurf* pTrg = CerfWrapSurfobj(&tTrg, psoTarget);
    if (!pPat || !pTrg) return FALSE;

    const EGPEFormat pat_fmt = (pTrg->Format() == gpe24Bpp) ? gpe32Bpp : pTrg->Format();
    const BOOL temporary = (pPat->Format() != pat_fmt) ||
                           (pxlo && pxlo->flXlate != XO_TRIVIAL);

    int   stride;
    ULONG needed = sizeof(GPESurf);
    if (temporary) {
        stride  = (((pPat->Width() * CerfEGPEFormatBpp(pat_fmt) + 7) / 8) + 3) & ~3;
        needed += (ULONG)stride * (ULONG)pPat->Height();
    } else {
        stride = pPat->Stride();
    }

    GPESurf* brush = (GPESurf*)BRUSHOBJ_pvAllocRbrush(pbo, needed);
    if (!brush) return FALSE;

    void* bits;
    if (temporary) {
        bits = (void*)((((ULONG_PTR)brush + sizeof(GPESurf)) + 3u) & ~(ULONG_PTR)3u);
    } else {
        bits = pPat->Buffer();
    }
    brush->Init(pPat->Width(), pPat->Height(), bits, stride, pat_fmt);
    if (!temporary) return TRUE;

    RECTL rcl;
    rcl.left = 0; rcl.top = 0;
    rcl.right = pPat->Width(); rcl.bottom = pPat->Height();

    GPE* pGPE = GetGPE();
    GPEBltParms parms;
    memset(&parms, 0, sizeof(parms));
    parms.pDst       = brush;
    parms.pSrc       = pPat;
    parms.prclDst    = &rcl;
    parms.prclSrc    = &rcl;
    parms.rop4       = 0xCCCCu;
    parms.solidColor = 0xFFFFFFFFu;
    parms.xPositive  = 1;
    parms.yPositive  = 1;
    parms.blendFunction.SourceConstantAlpha = 0xFF;

    BOOL lookup_owned = FALSE;
    if (pxlo && pxlo->flXlate != XO_TRIVIAL) {
        CerfSetSurfaceFormat(brush, pxlo, XO_DESTPALETTE);
        CerfSetSurfaceFormat(pPat, pxlo, XO_SRCPALETTE);
        if (!CerfDecodeXlate(pxlo, &parms, &lookup_owned))
            return CerfBltFail(brush, pPat, &parms, lookup_owned);
    }

    SCODE sc = pGPE->BltPrepare(&parms);
    if (!FAILED(sc)) sc = (pGPE->*parms.pBlt)(&parms);
    pGPE->BltComplete(&parms);

    CerfReleaseSurfaceFormat(brush);
    if (lookup_owned && parms.pLookup) delete[] parms.pLookup;
    CerfReleaseSurfaceFormat(pPat);
    return !FAILED(sc);
}

extern "C" BOOL APIENTRY DrvCopyBits(SURFOBJ*, SURFOBJ*, CLIPOBJ*, XLATEOBJ*,
                                     RECTL*, POINTL*) {
    return FALSE;
}
