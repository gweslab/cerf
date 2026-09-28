#include <windows.h>
#include <winddi.h>

#include "include/cerf_gpe.h"
#include "include/cerf_ddi.h"
#include "include/cerf_surfobj.h"
#include "cerf_ddgpe.h"
#include "cerf_eng_callbacks.h"

#define CERF_FILL_SWAP(type, a, b) { type tmp = (a); (a) = (b); (b) = tmp; }

struct CerfEdge {
    int       yTop;
    CerfEdge* pNextTop;
    int       yBottom;
    CerfEdge* pNextBottom;
    int       fx;
    CerfEdge* pNextActive;
    int       direction;
    int       fxTop;
    int       fxIntegralAdvance;
    int       fxNumeratorAdvance;
    int       fxNumerator;
    int       fxNumeratorStart;
    int       fdyHeight;
};

class CerfEdgeList {
public:
    explicit CerfEdgeList(int nAlloc) {
        m_aEdge = (CerfEdge*)LocalAlloc(LMEM_FIXED, nAlloc * sizeof(CerfEdge));
        m_nListSize = m_aEdge ? nAlloc : 0;
        m_nNumEdges = 0;
        m_pFirstTop = m_pFirstBottom = NULL;
        m_pFirstActive = NULL;
        m_nyMin = m_nyMax = 0;
    }
    ~CerfEdgeList() { if (m_aEdge) LocalFree((HLOCAL)m_aEdge); }

    SCODE AddEdge(long fx0, long fy0, long fx1, long fy1);
    SCODE Fill(GPEBltParms* pParms, RECTL* prclClip, GPE* pGPE);

private:
    CerfEdge* m_aEdge;
    CerfEdge* m_pFirstTop;
    CerfEdge* m_pFirstBottom;
    CerfEdge* m_pFirstActive;
    int       m_nListSize;
    int       m_nNumEdges;
    int       m_nyMin;
    int       m_nyMax;
};

SCODE CerfEdgeList::AddEdge(long fx0, long fy0, long fx1, long fy1) {
    int fdx, fdy, fxIntegralAdvance, fxNumeratorAdvance, fxNumerator;

    if (m_nListSize <= m_nNumEdges) {
        CerfEdge* pNewList = m_aEdge
            ? (CerfEdge*)LocalReAlloc((HLOCAL)m_aEdge,
                                      (m_nListSize + 200) * sizeof(CerfEdge), LMEM_MOVEABLE)
            : (CerfEdge*)LocalAlloc(LMEM_FIXED, (m_nListSize + 200) * sizeof(CerfEdge));
        if (!pNewList) return E_OUTOFMEMORY;
        m_nListSize += 200;
        m_aEdge = pNewList;
    }

    if (fy0 < fy1) {
        m_aEdge[m_nNumEdges].direction = 1;
    } else {
        m_aEdge[m_nNumEdges].direction = -1;
        CERF_FILL_SWAP(long, fy0, fy1);
        CERF_FILL_SWAP(long, fx0, fx1);
    }

    if (((fy0 + 15) & ~15) >= ((fy1 + 15) & ~15)) return S_OK;

    fdx = fx1 - fx0;
    fdy = fy1 - fy0;
    fxIntegralAdvance  = fdx / fdy;
    fxNumeratorAdvance = fdx % fdy;
    fxNumerator = 0;

    while (fy0 & 15) {
        fy0++;
        fx0 += fxIntegralAdvance;
        fxNumerator += fxNumeratorAdvance;
        if (fxNumeratorAdvance >= 0) {
            if (fxNumerator > 0) { fxNumerator -= fdy; fx0++; }
        } else {
            if (fxNumerator <= -fdy) { fxNumerator += fdy; fx0--; }
        }
    }

    m_aEdge[m_nNumEdges].yTop               = fy0 >> 4;
    m_aEdge[m_nNumEdges].yBottom            = (fy1 + 15) >> 4;
    m_aEdge[m_nNumEdges].fxTop              = fx0;
    m_aEdge[m_nNumEdges].pNextTop           = NULL;
    m_aEdge[m_nNumEdges].pNextBottom        = NULL;
    m_aEdge[m_nNumEdges].fxIntegralAdvance  = (fdx * 16) / fdy;
    m_aEdge[m_nNumEdges].fxNumeratorAdvance = (fdx * 16) % fdy;
    m_aEdge[m_nNumEdges].fdyHeight          = fdy;
    m_aEdge[m_nNumEdges].fxNumeratorStart   = fxNumerator;
    m_nNumEdges++;
    return S_OK;
}

SCODE CerfEdgeList::Fill(GPEBltParms* pParms, RECTL* prclClip, GPE* pGPE) {
    CerfEdge** ppEdge;
    CerfEdge*  pEdge;
    SCODE      sc;
    RECTL      rclDst;
    pParms->prclDst = &rclDst;
    int y, edgeCount, xLeft, xRight, fSwapped;

    if (m_nNumEdges < 1) return S_OK;

    if (!m_pFirstTop) {
        int newEdgeNo;
        for (pEdge = m_aEdge, newEdgeNo = 0; newEdgeNo < m_nNumEdges;
             newEdgeNo++, pEdge++) {
            for (ppEdge = &m_pFirstTop;
                 (*ppEdge != NULL) && (pEdge->yTop > (*ppEdge)->yTop);
                 ppEdge = &((*ppEdge)->pNextTop));
            pEdge->pNextTop = *ppEdge;
            *ppEdge = pEdge;

            for (ppEdge = &m_pFirstBottom;
                 (*ppEdge != NULL) && (pEdge->yBottom > (*ppEdge)->yBottom);
                 ppEdge = &((*ppEdge)->pNextBottom));
            if (*ppEdge == NULL) m_nyMax = pEdge->yBottom;
            pEdge->pNextBottom = *ppEdge;
            *ppEdge = pEdge;
        }
        m_nyMin = m_pFirstTop->yTop;
    }

    if (prclClip && (m_nyMin >= prclClip->bottom || m_nyMax < prclClip->top))
        return S_OK;

    CerfEdge* pTopList    = m_pFirstTop;
    CerfEdge* pBottomList = m_pFirstBottom;
    m_pFirstActive = NULL;

    for (y = m_nyMin; y < m_nyMax; y++) {
        if (prclClip && (y >= prclClip->bottom)) break;

        pParms->prclDst->top    = y;
        pParms->prclDst->bottom = y + 1;

        for (; pTopList && (pTopList->yTop <= y); pTopList = pTopList->pNextTop) {
            pTopList->fxNumerator = pTopList->fxNumeratorStart;
            pTopList->fx          = pTopList->fxTop;
            for (ppEdge = &m_pFirstActive;
                 (*ppEdge != NULL) && (pTopList->fx > (*ppEdge)->fx);
                 ppEdge = &((*ppEdge)->pNextActive));
            pTopList->pNextActive = *ppEdge;
            *ppEdge = pTopList;
        }

        for (; pBottomList && (pBottomList->yBottom <= y);
             pBottomList = pBottomList->pNextBottom) {
            for (ppEdge = &m_pFirstActive;
                 (*ppEdge != NULL) && (*ppEdge != pBottomList);
                 ppEdge = &((*ppEdge)->pNextActive));
            if (*ppEdge) *ppEdge = (*ppEdge)->pNextActive;
        }

        do {
            fSwapped = 0;
            for (ppEdge = &m_pFirstActive;
                 (*ppEdge != NULL) && ((*ppEdge)->pNextActive != NULL);
                 ppEdge = &((*ppEdge)->pNextActive)) {
                pEdge = *ppEdge;
                if (pEdge->fx > pEdge->pNextActive->fx) {
                    fSwapped = 1;
                    *ppEdge = pEdge->pNextActive;
                    pEdge->pNextActive = pEdge->pNextActive->pNextActive;
                    (*ppEdge)->pNextActive = pEdge;
                }
            }
        } while (fSwapped);

        edgeCount = 0;
        if (!prclClip || (y >= prclClip->top)) {
            for (pEdge = m_pFirstActive; pEdge; pEdge = pEdge->pNextActive) {
                xLeft = (pEdge->fx + 15) >> 4;
                for (edgeCount = pEdge->direction; edgeCount;) {
                    pEdge = pEdge->pNextActive;
                    if (!pEdge) break;
                    edgeCount += pEdge->direction;
                }
                if (!pEdge) return E_INVALIDARG;
                xRight = (pEdge->fx + 15) >> 4;
                if (prclClip) {
                    if (xLeft  < prclClip->left)  xLeft  = prclClip->left;
                    if (xRight > prclClip->right) xRight = prclClip->right;
                }
                if (xLeft < xRight) {
                    pParms->prclDst->left  = xLeft;
                    pParms->prclDst->right = xRight;
                    if (FAILED(sc = (pGPE->*(pParms->pBlt))(pParms))) return sc;
                }
            }
        }

        for (pEdge = m_pFirstActive; pEdge; pEdge = pEdge->pNextActive) {
            pEdge->fx          += pEdge->fxIntegralAdvance;
            pEdge->fxNumerator += pEdge->fxNumeratorAdvance;
            if (pEdge->fxNumeratorAdvance >= 0) {
                if (pEdge->fxNumerator > 0) {
                    pEdge->fxNumerator -= pEdge->fdyHeight;
                    pEdge->fx++;
                }
            } else {
                if (pEdge->fxNumerator <= -pEdge->fdyHeight) {
                    pEdge->fxNumerator += pEdge->fdyHeight;
                    pEdge->fx--;
                }
            }
        }
    }
    return S_OK;
}

extern "C" BOOL APIENTRY DrvFillPath(SURFOBJ* pso, PATHOBJ* ppo, CLIPOBJ* pco,
                                     BRUSHOBJ* pbo, POINTL* pptlBrushOrg,
                                     MIX mix, FLONG) {
    GPE* pGPE = GetGPE();
    if (!pGPE || !pso || !ppo || !pbo) return FALSE;

    CerfTmpSurf tDst;
    GPESurf* pDst = CerfWrapSurfobj(&tDst, pso);
    if (!pDst) return FALSE;

    CerfEdgeList edgeList(ppo->cCurves);

    GPEBltParms parms;
    memset(&parms, 0, sizeof(parms));
    parms.pDst       = pDst;
    parms.xPositive  = 1;
    parms.yPositive  = 1;
    parms.pptlBrush  = pptlBrushOrg;
    parms.rop4       = (((ROP4)kCerfMixToRop3[(mix >> 8) & 0x0f]) << 8)
                     | kCerfMixToRop3[mix & 0x0f];
    parms.solidColor = pbo->iSolidColor;
    parms.blendFunction.SourceConstantAlpha = 0xFF;

    if (pbo->iSolidColor == 0xffffffffu) {
        void* rb = pbo->pvRbrush ? pbo->pvRbrush : BRUSHOBJ_pvGetRbrush(pbo);
        if (!rb) return FALSE;
        parms.pBrush = (GPESurf*)rb;
    }

    if (FAILED(pGPE->BltPrepare(&parms))) return FALSE;

    POINTFIX firstPoint = { 0, 0 };
    POINTFIX lastPoint  = { 0, 0 };
    PATHDATA pd;
    int      bMore, bFailed = 0, i = 0;

    PATHOBJ_vEnumStart(ppo);
    do {
        bMore = PATHOBJ_bEnum(ppo, &pd);
        int cptfx = (int)pd.count;
        if (!cptfx) break;

        if (pd.flags & PD_BEGINSUBPATH) {
            firstPoint = pd.pptfx[0];
        } else {
            if (FAILED(edgeList.AddEdge(lastPoint.x, lastPoint.y,
                                        pd.pptfx[0].x, pd.pptfx[0].y))) {
                bMore = 0; bFailed = 1;
            }
        }

        for (i = 0; i < cptfx - 1; i++) {
            if (FAILED(edgeList.AddEdge(pd.pptfx[i].x, pd.pptfx[i].y,
                                        pd.pptfx[i + 1].x, pd.pptfx[i + 1].y))) {
                bMore = 0; bFailed = 1;
            }
        }

        if (pd.flags & PD_ENDSUBPATH) {
            if (FAILED(edgeList.AddEdge(pd.pptfx[i].x, pd.pptfx[i].y,
                                        firstPoint.x, firstPoint.y))) {
                bMore = 0; bFailed = 1;
            }
        } else {
            lastPoint = pd.pptfx[i];
        }
    } while (bMore);

    SCODE sc1 = S_OK;
    if ((pco == NULL) || (pco->iDComplexity == DC_TRIVIAL)) {
        sc1 = edgeList.Fill(&parms, NULL, pGPE);
    } else if (pco->iDComplexity == DC_RECT) {
        sc1 = edgeList.Fill(&parms, &pco->rclBounds, pGPE);
    } else {
        ENUMRECTS ce;
        RECTL* prclCurr;
        int moreClipLists;
        CLIPOBJ_cEnumStart(pco, TRUE, CT_RECTANGLES, CD_ANY, 0);
        for (ce.c = 0, moreClipLists = 1, prclCurr = ce.arcl;
             ce.c || moreClipLists;) {
            if (ce.c == 0) {
                moreClipLists = CLIPOBJ_bEnum(pco, sizeof(ce), (ULONG*)&ce);
                prclCurr = ce.arcl;
                if (!ce.c) continue;
            }
            ce.c--;
            if (FAILED(sc1 = edgeList.Fill(&parms, prclCurr++, pGPE))) break;
        }
    }

    SCODE sc2 = pGPE->BltComplete(&parms);
    return (!FAILED(sc1)) && (!FAILED(sc2)) && (!bFailed);
}
