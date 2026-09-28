#include <windows.h>
#include <winddi.h>

#include "include/cerf_gpe.h"
#include "include/cerf_ddi.h"
#include "include/cerf_surfobj.h"
#include "cerf_ddgpe.h"
#include "cerf_eng_callbacks.h"

#define FL_H_ROUND_DOWN   0x00000080L
#define FL_V_ROUND_DOWN   0x00008000L
#define FL_FLIP_D         0x00000005L
#define FL_FLIP_V         0x00000008L
#define FL_FLIP_SLOPE_ONE 0x00000010L
#define FL_FLIP_H         0x00000200L
#define FL_ROUND_MASK     0x0000001CL
#define FL_ROUND_SHIFT    2
#define FL_RECTLCLIP_MASK 0x0000000CL
#define FL_RECTLCLIP_SHIFT 2

#define CERF_STROKE_CLIP_LIMIT 50

#define CERF_SWAP(a, b, type) { type tmp = (a); (a) = (b); (b) = tmp; }

static const FLONG gaflRound[] = {
    FL_H_ROUND_DOWN | FL_V_ROUND_DOWN,
    FL_H_ROUND_DOWN | FL_V_ROUND_DOWN,
    FL_H_ROUND_DOWN,
    FL_V_ROUND_DOWN,
    FL_V_ROUND_DOWN,
    0xbaadf00d,
    FL_H_ROUND_DOWN,
    0xbaadf00d
};

typedef struct _CerfStrokeClipEnum {
    LONG  c;
    RECTL arcl[CERF_STROKE_CLIP_LIMIT];
} CerfStrokeClipEnum;

extern "C" BOOL APIENTRY DrvStrokePath(SURFOBJ* pso, PATHOBJ* ppo, CLIPOBJ* pco,
                                       XFORMOBJ*, BRUSHOBJ* pbo, POINTL*,
                                       LINEATTRS* plineattrs, MIX mix) {
    GPE* pGPE = GetGPE();
    if (!pGPE || !pso || !ppo || !pbo) return FALSE;

    CerfTmpSurf tDst;
    GPESurf* pDst = CerfWrapSurfobj(&tDst, pso);
    if (!pDst) return FALSE;

    if (pDst->IsRotate()) {
        CERF_LOG("cerf_guest: UNIMPLEMENTED DrvStrokePath on rotated surface");
        return FALSE;
    }

    GPELineParms parms;
    memset(&parms, 0, sizeof(parms));
    parms.solidColor = pbo->iSolidColor;
    parms.mix        = (unsigned short)mix;
    parms.pDst       = pDst;
    parms.style      = 0;

    if (plineattrs && (((mix >> 8) & 0x00ff) != (mix & 0x00ff))) {
        if (plineattrs->fl & LA_ALTERNATE) {
            parms.style = 0xaaaaaaaa;
        } else if (plineattrs->pstyle && plineattrs->cstyle) {
            int bitno = 0, bitval = 0, dashno;
            for (dashno = 0; bitno < 32; dashno++) {
                dashno %= plineattrs->cstyle;
                int dashpixel;
                for (dashpixel = 0;
                     (dashpixel < plineattrs->pstyle[dashno].l) && (bitno < 32);
                     dashpixel++, bitno++)
                    parms.style |= (bitval << bitno);
                bitval ^= 1;
                if (dashno == 64) { parms.style = 0; break; }
            }
        }
        if (plineattrs->fl & LA_STARTGAP) parms.style = ~(parms.style);
    }

    if (FAILED(pGPE->Line(&parms, gpePrepare))) return FALSE;

    RECTL  rclBounds;
    RECTL* prclCurr;
    int    moreClipLists;
    if ((pco == NULL) || (pco->iDComplexity == DC_TRIVIAL)) {
        prclCurr = &rclBounds;
        moreClipLists = 0;
        rclBounds.top    = 0;
        rclBounds.left   = 0;
        rclBounds.right  = parms.pDst->Width();
        rclBounds.bottom = parms.pDst->Height();
    } else if (pco->iDComplexity == DC_RECT) {
        prclCurr = &pco->rclBounds;
        moreClipLists = 0;
    } else {
        prclCurr = NULL;
        moreClipLists = 1;
        CLIPOBJ_cEnumStart(pco, TRUE, CT_RECTANGLES, CD_ANY, 0);
    }

    CerfStrokeClipEnum ce;
    for (ce.c = 1 - moreClipLists; ce.c || moreClipLists; prclCurr++, ce.c--) {
        if (ce.c == 0) {
            moreClipLists = CLIPOBJ_bEnum(pco, sizeof(ce), (ULONG*)&ce);
            prclCurr = ce.arcl;
            if (!ce.c) continue;
        }

        parms.styleState = 0;

        RECTL arclClip[8];
        arclClip[0] = *prclCurr;
        arclClip[1].top    =  prclCurr->left;
        arclClip[1].left   =  prclCurr->top;
        arclClip[1].bottom =  prclCurr->right;
        arclClip[1].right  =  prclCurr->bottom;
        arclClip[2].top    = -prclCurr->bottom + 1;
        arclClip[2].left   =  prclCurr->left;
        arclClip[2].bottom = -prclCurr->top + 1;
        arclClip[2].right  =  prclCurr->right;
        arclClip[3].top    =  prclCurr->left;
        arclClip[3].left   = -prclCurr->bottom + 1;
        arclClip[3].bottom =  prclCurr->right;
        arclClip[3].right  = -prclCurr->top + 1;
        arclClip[4].top    =  prclCurr->top;
        arclClip[4].left   = -prclCurr->right + 1;
        arclClip[4].bottom =  prclCurr->bottom;
        arclClip[4].right  = -prclCurr->left + 1;
        arclClip[5].top    = -prclCurr->right + 1;
        arclClip[5].left   =  prclCurr->top;
        arclClip[5].bottom = -prclCurr->left + 1;
        arclClip[5].right  =  prclCurr->bottom;
        arclClip[6].top    = -prclCurr->bottom + 1;
        arclClip[6].left   = -prclCurr->right + 1;
        arclClip[6].bottom = -prclCurr->top + 1;
        arclClip[6].right  = -prclCurr->left + 1;
        arclClip[7].top    = -prclCurr->right + 1;
        arclClip[7].left   = -prclCurr->bottom + 1;
        arclClip[7].bottom = -prclCurr->left + 1;
        arclClip[7].right  = -prclCurr->top + 1;

        POINTFIX ptfxStartFigure, ptfxLast;
        PATHDATA pd;
        int      morePointLists;

        PATHOBJ_vEnumStart(ppo);
        do {
            morePointLists = PATHOBJ_bEnum(ppo, &pd);
            ULONG cptfx = pd.count;
            if (!cptfx) break;

            POINTFIX* pptfxPrev;
            POINTFIX* pptfxBuf;
            if (pd.flags & PD_BEGINSUBPATH) {
                ptfxStartFigure = *pd.pptfx;
                pptfxPrev = pd.pptfx;
                pptfxBuf  = pd.pptfx + 1;
                cptfx--;
            } else {
                pptfxPrev = &ptfxLast;
                pptfxBuf  = pd.pptfx;
            }

            for (ULONG pointNo = 0; pointNo <= cptfx; pointNo++) {
                FIX fx0, fy0, fx1, fy1;
                if (pointNo < cptfx) {
                    fx0 = pptfxPrev->x; fy0 = pptfxPrev->y;
                    fx1 = pptfxBuf->x;  fy1 = pptfxBuf->y;
                    pptfxPrev = pptfxBuf++;
                } else {
                    ptfxLast = pd.pptfx[pd.count - 1];
                    if (!(pd.flags & PD_CLOSEFIGURE)) break;
                    fx0 = ptfxLast.x;         fy0 = ptfxLast.y;
                    fx1 = ptfxStartFigure.x;  fy1 = ptfxStartFigure.y;
                }

                unsigned long fl = 0;
                if (fx1 < fx0) { fx0 = -fx0; fx1 = -fx1; fl |= FL_FLIP_H; }
                if (fy1 < fy0) { fy0 = -fy0; fy1 = -fy1; fl |= FL_FLIP_V; }
                if ((fy1 - fy0) > (fx1 - fx0)) {
                    CERF_SWAP(fx0, fy0, FIX);
                    CERF_SWAP(fx1, fy1, FIX);
                    fl |= FL_FLIP_D;
                }

                FIX dM = fx1 - fx0;
                FIX dN = fy1 - fy0;
                if (dM == dN) fl |= FL_FLIP_SLOPE_ONE;
                fl |= gaflRound[(fl & FL_ROUND_MASK) >> FL_ROUND_SHIFT];

                unsigned long x = fx0 >> 4;
                unsigned long y = fy0 >> 4;
                FIX M0 = fx0 & 0x000f;
                FIX N0 = fy0 & 0x000f;

                long llGamma = (dM * (N0 + 8) - dN * M0
                                - ((fl & FL_V_ROUND_DOWN) ? 1 : 0)) >> 4;
                FIX M1 = (M0 + dM) & 0x000f;
                FIX N1 = (N0 + dN) & 0x000f;

                unsigned long x0, y0, x1;
                long errorTerm;
                x1 = (M0 + dM) >> 4;
                {
                    x1--;
                    if (M1 > 0) {
                        if (N1 == 0) {
                            if (M1 > ((fl & FL_H_ROUND_DOWN) ? 8 : 7)) x1++;
                        } else if (((N1 < 8) ? (8 - N1) : (N1 - 8)) <= M1) {
                            x1++;
                        }
                    }
                    x0 = 0;
                    if ((fl & (FL_FLIP_SLOPE_ONE | FL_H_ROUND_DOWN))
                        == (FL_FLIP_SLOPE_ONE | FL_H_ROUND_DOWN)) {
                        if ((M1 > 0) && (N1 == M1 + 8)) x1--;
                        if ((M0 > 0) && (N0 == M0 + 8)) goto left_to_right_compute_y0;
                    }
                    if (M0 > 0) {
                        if (N0 == 0) {
                            if (M0 > ((fl & FL_H_ROUND_DOWN) ? 8 : 7)) x0 = 1;
                        } else if (((N0 < 8) ? (8 - N0) : (N0 - 8)) <= M0) {
                            x0 = 1;
                        }
                    }
                    left_to_right_compute_y0:
                    if (llGamma >= (long)(dM - (dN & (-(long)x0)))) {
                        errorTerm = llGamma + (dN & ~(x0 - 1)) - 2 * dM;
                        y0 = 1;
                    } else {
                        errorTerm = llGamma + (dN & ~(x0 - 1)) - dM;
                        y0 = 0;
                    }
                }
                llGamma = errorTerm;

                int cStylePels = x1 - x0 + 1;
                if (cStylePels <= 0) continue;

                RECTL* prclFlipped = &arclClip[(fl & FL_RECTLCLIP_MASK) >> FL_RECTLCLIP_SHIFT];
                if (fl & FL_FLIP_H) prclFlipped += 4;
                int xRight  = prclFlipped->right  - x;
                int xLeft   = prclFlipped->left   - x;
                int yTop    = prclFlipped->top    - y;
                int yBottom = prclFlipped->bottom - y;

                if ((long)y0 >= yBottom || (long)x0 >= xRight || (long)x1 < xLeft)
                    continue;
                if ((long)x1 >= xRight) x1 = xRight - 1;

                unsigned long y1;
                if (dM == 0 || dN == 0) {
                    if ((long)x0 < xLeft) x0 = (unsigned long)xLeft;
                    if ((long)y0 < yTop) continue;
                    y1 = y0;
                } else {
                    if ((long)x0 < xLeft) {
                        y0 = y0 + (unsigned long)((xLeft - (long)x0) * dN + llGamma + dM) / dM;
                        x0 = (unsigned long)xLeft;
                        if ((long)y0 >= yBottom) continue;
                    }
                    if ((long)y0 < yTop) {
                        x0 = 1 + x0 + (unsigned long)((yTop - (long)y0 - 1) * dM - llGamma - 1) / dN;
                        y0 = (unsigned long)yTop;
                        if ((long)x0 >= xRight) continue;
                    }
                    y1 = y0 + (unsigned long)(((long)((x1 - x0) * dN) + llGamma + dM) / dM);
                    if ((long)y1 < yTop) continue;
                    if ((long)y1 >= yBottom) {
                        y1 = (unsigned long)(yBottom - 1);
                        x1 = (unsigned long)(x0 + ((long)(y1 - y0) * dM - llGamma - 1) / dN);
                        if ((long)x1 < xLeft) continue;
                    }
                }

                long xStart = x + x0;
                long yStart = y + y0;
                if (fl & FL_FLIP_D) { CERF_SWAP(xStart, yStart, long); }
                if (fl & FL_FLIP_V) yStart = -yStart;
                if (fl & FL_FLIP_H) xStart = -xStart;

                int iDir = ((fl & FL_FLIP_V) ? 7 : 0) ^ ((fl & FL_FLIP_D) ? 1 : 0)
                         ^ ((fl & FL_FLIP_H) ? 3 : 0);
                int cPels = x1 - x0 + 1;
                if (cPels <= 0) continue;

                parms.xStart   = xStart;
                parms.yStart   = yStart;
                parms.cPels    = cPels;
                parms.dM       = dM;
                parms.dN       = dN;
                parms.llGamma  = errorTerm;
                parms.iDir     = iDir;
                parms.prclClip = prclCurr;

                if (FAILED((pGPE->*(parms.pLine))(&parms))) return FALSE;

                parms.styleState = (parms.styleState + cStylePels) & 31;
            }
        } while (morePointLists);
    }

    pGPE->Line(&parms, gpeComplete);
    return TRUE;
}
