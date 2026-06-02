#include <windows.h>
#include <pkfuncs.h>
#include <winddi.h>
#include <gpe.h>
#include "cerf/peripherals/cerf_virt/cerf_virt_grad_descriptor.h"
#include "cerf/peripherals/cerf_virt/cerf_virt_gpe_cmd.h"

/* CE6 winddi.h omits the StretchBlt mode constants; AnyBlt's iMode is unused
   for a 1:1 alpha blt but stock (sub_17D3C94) passes BLACKONWHITE. */
#ifndef BLACKONWHITE
#define BLACKONWHITE 1
#endif

/* DDI slots 27/28 (DrvGradientFill / DrvAlphaBlend), host-accelerated. */

extern "C" ULONG CerfGpeGrad(ULONG desc_va);
extern "C" void  CerfFillSurfaceFromSurfobj(CerfVirt::CerfBltSurface* s, SURFOBJ* pso);

/* GPE engine clip-enumeration callbacks, populated by DrvEnableDriver. */
extern PFN_CLIPOBJ_cEnumStart CLIPOBJ_cEnumStart;
extern PFN_CLIPOBJ_bEnum      CLIPOBJ_bEnum;

/* GPE lib bridge that carries the BLENDFUNCTION into GPEBltParms and runs
   BltPrepare -> HwBlt (so alpha lands on the host). Internal C++ symbol, not an
   extern "C" DDI export — declaring it extern "C" would fail to link. */
extern BOOL APIENTRY AnyBlt(SURFOBJ*, SURFOBJ*, SURFOBJ*, CLIPOBJ*, XLATEOBJ*,
                            RECTL*, RECTL*, POINTL*, BRUSHOBJ*, POINTL*,
                            ROP4, unsigned long, int, BLENDFUNCTION);

static void CerfRectIntersect(CerfVirt::CerfBltRect* out,
                              const RECTL& a, const RECTL& b) {
    out->left   = a.left   > b.left   ? a.left   : b.left;
    out->top    = a.top    > b.top    ? a.top    : b.top;
    out->right  = a.right  < b.right  ? a.right  : b.right;
    out->bottom = a.bottom < b.bottom ? a.bottom : b.bottom;
}

/* Paint the gradient ramp described by g over (its rect) intersected with each
   clip rectangle. Per-clip-rect emission keeps the host op faithful for complex
   clips: the colour is anchored to absolute coords, so sub-rects compose. */
static BOOL CerfEmitGradient(CerfVirt::CerfGradDescriptor& g, const RECTL& grect,
                             CLIPOBJ* pco) {
    if (!pco || pco->iDComplexity == DC_TRIVIAL) {
        g.fill_rect.left = grect.left;  g.fill_rect.top    = grect.top;
        g.fill_rect.right = grect.right; g.fill_rect.bottom = grect.bottom;
        return CerfGpeGrad((ULONG)(ULONG_PTR)&g) == CerfVirt::kGpeStatusDone;
    }
    if (pco->iDComplexity == DC_RECT) {
        CerfRectIntersect(&g.fill_rect, grect, pco->rclBounds);
        if (g.fill_rect.right <= g.fill_rect.left ||
            g.fill_rect.bottom <= g.fill_rect.top) return TRUE;
        return CerfGpeGrad((ULONG)(ULONG_PTR)&g) == CerfVirt::kGpeStatusDone;
    }

    struct { ULONG c; RECTL arcl[24]; } eb;
    CLIPOBJ_cEnumStart(pco, TRUE, CT_RECTANGLES, CD_ANY, 0);
    BOOL more, ok = TRUE;
    do {
        more = CLIPOBJ_bEnum(pco, sizeof(eb), (ULONG*)&eb);
        for (ULONG i = 0; i < eb.c; ++i) {
            CerfRectIntersect(&g.fill_rect, grect, eb.arcl[i]);
            if (g.fill_rect.right <= g.fill_rect.left ||
                g.fill_rect.bottom <= g.fill_rect.top) continue;
            if (CerfGpeGrad((ULONG)(ULONG_PTR)&g) != CerfVirt::kGpeStatusDone) ok = FALSE;
        }
    } while (more);
    return ok;
}

extern "C" BOOL APIENTRY CerfDrvGradientFill(SURFOBJ* pso, CLIPOBJ* pco,
                                              XLATEOBJ* /*pxlo*/,
                                              TRIVERTEX* pVertex, ULONG nVertex,
                                              PVOID pMesh, ULONG nMesh,
                                              RECTL* /*prclExtents*/,
                                              POINTL* /*pptlDitherOrg*/, ULONG ulMode) {
    if (!pso || !pVertex || !pMesh) return FALSE;
    const ULONG op = ulMode & GRADIENT_FILL_OP_FLAG;
    /* gwes (sub_82378) rejects every mode but RECT_H/RECT_V before the driver. */
    if (op != GRADIENT_FILL_RECT_H && op != GRADIENT_FILL_RECT_V) return FALSE;
    const bool horiz = (op == GRADIENT_FILL_RECT_H);

    CerfVirt::CerfGradDescriptor g;
    memset(&g, 0, sizeof(g));
    g.magic = CerfVirt::kCerfGradMagic;
    g.axis  = horiz ? CerfVirt::kCerfGradAxisH : CerfVirt::kCerfGradAxisV;
    CerfFillSurfaceFromSurfobj(&g.dst, pso);

    const GRADIENT_RECT* mesh = (const GRADIENT_RECT*)pMesh;
    BOOL ok = TRUE;
    for (ULONG i = 0; i < nMesh; ++i) {
        if (mesh[i].UpperLeft >= nVertex || mesh[i].LowerRight >= nVertex) continue;
        const TRIVERTEX* v0 = &pVertex[mesh[i].UpperLeft];
        const TRIVERTEX* v1 = &pVertex[mesh[i].LowerRight];

        /* start = lower coord on the gradient axis; cross axis spans min..max
           (sub_17D3434 orders the two vertices then swaps the off-axis values). */
        const TRIVERTEX* a = v0;
        const TRIVERTEX* b = v1;
        RECTL gr;
        if (horiz) {
            if (a->x > b->x) { const TRIVERTEX* t = a; a = b; b = t; }
            gr.left = a->x; gr.right = b->x;
            gr.top    = (v0->y < v1->y) ? v0->y : v1->y;
            gr.bottom = (v0->y < v1->y) ? v1->y : v0->y;
        } else {
            if (a->y > b->y) { const TRIVERTEX* t = a; a = b; b = t; }
            gr.top = a->y; gr.bottom = b->y;
            gr.left  = (v0->x < v1->x) ? v0->x : v1->x;
            gr.right = (v0->x < v1->x) ? v1->x : v0->x;
        }
        if (gr.right <= gr.left || gr.bottom <= gr.top) continue;

        g.start_coord = horiz ? gr.left : gr.top;
        g.end_coord   = horiz ? gr.right : gr.bottom;
        g.start_color[0] = a->Red; g.start_color[1] = a->Green;
        g.start_color[2] = a->Blue; g.start_color[3] = a->Alpha;
        g.end_color[0]   = b->Red; g.end_color[1]   = b->Green;
        g.end_color[2]   = b->Blue; g.end_color[3]   = b->Alpha;

        if (!CerfEmitGradient(g, gr, pco)) ok = FALSE;
    }
    return ok;
}

extern "C" BOOL APIENTRY CerfDrvAlphaBlend(SURFOBJ* psoDest, SURFOBJ* psoSrc,
                                            CLIPOBJ* pco, XLATEOBJ* pxlo,
                                            RECTL* prclDest, RECTL* prclSrc,
                                            BLENDOBJ* pBlendObj) {
    if (!psoDest || !psoSrc || !prclDest || !prclSrc || !pBlendObj) return FALSE;
    return AnyBlt(psoDest, psoSrc, NULL, pco, pxlo, prclDest, prclSrc,
                  NULL, NULL, NULL, 0xCCCC, BLT_ALPHABLEND, BLACKONWHITE,
                  pBlendObj->BlendFunction);
}
