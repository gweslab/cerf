#include <windows.h>
#include <pkfuncs.h>
#include <winddi.h>
#include "include/cerf_gpe.h"
#include "include/cerf_ddi.h"
#include "cerf_ddgpe.h"
#include "cerf_dma_arena.h"
#include "cerf_debug_log.h"
#include "cerf_eng_callbacks.h"
#include "cerf_gradient.h"
#include "main.h"
#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"
#include "cerf/peripherals/cerf_virt/cerf_virt_grad_descriptor.h"
#include "cerf/peripherals/cerf_virt/cerf_virt_gpe_cmd.h"

#ifndef BLACKONWHITE
#define BLACKONWHITE 1
#endif

static void CerfRectIntersect(CerfVirt::CerfBltRect* out,
                              const RECTL& a, const RECTL& b) {
    RECTL r = a;
    CerfRectClamp(&r, &b);
    out->left = r.left; out->top = r.top; out->right = r.right; out->bottom = r.bottom;
}

static BOOL CerfEmitGradient(CerfVirt::CerfGradDescriptor& g, ULONG desc_off,
                             const RECTL& grect_in, CLIPOBJ* pco, int W, int H) {
    RECTL grect = grect_in;
    RECTL sbound;
    sbound.left = 0; sbound.top = 0; sbound.right = W; sbound.bottom = H;
    CerfRectClamp(&grect, &sbound);
    if (grect.right <= grect.left || grect.bottom <= grect.top) return TRUE;
    if (!pco || pco->iDComplexity == DC_TRIVIAL) {
        g.fill_rect.left = grect.left;  g.fill_rect.top    = grect.top;
        g.fill_rect.right = grect.right; g.fill_rect.bottom = grect.bottom;
        return CerfGpeGrad(desc_off) == CerfVirt::kGpeStatusDone;
    }
    if (pco->iDComplexity == DC_RECT) {
        CerfRectIntersect(&g.fill_rect, grect, pco->rclBounds);
        if (g.fill_rect.right <= g.fill_rect.left ||
            g.fill_rect.bottom <= g.fill_rect.top) return TRUE;
        return CerfGpeGrad(desc_off) == CerfVirt::kGpeStatusDone;
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
            if (CerfGpeGrad(desc_off) != CerfVirt::kGpeStatusDone) ok = FALSE;
        }
    } while (more);
    return ok;
}

static BOOL CerfGradMeshRect(const GRADIENT_RECT* m, const TRIVERTEX* pVertex,
                             ULONG nVertex, bool horiz, RECTL* gr,
                             const TRIVERTEX** pa, const TRIVERTEX** pb) {
    if (m->UpperLeft >= nVertex || m->LowerRight >= nVertex) return FALSE;
    const TRIVERTEX* v0 = &pVertex[m->UpperLeft];
    const TRIVERTEX* v1 = &pVertex[m->LowerRight];
    const TRIVERTEX* a = v0;
    const TRIVERTEX* b = v1;
    RECTL r;
    if (horiz) {
        if (a->x > b->x) { const TRIVERTEX* t = a; a = b; b = t; }
        r.left = a->x; r.right = b->x;
        r.top    = (v0->y < v1->y) ? v0->y : v1->y;
        r.bottom = (v0->y < v1->y) ? v1->y : v0->y;
    } else {
        if (a->y > b->y) { const TRIVERTEX* t = a; a = b; b = t; }
        r.top = a->y; r.bottom = b->y;
        r.left  = (v0->x < v1->x) ? v0->x : v1->x;
        r.right = (v0->x < v1->x) ? v1->x : v0->x;
    }
    if (r.right <= r.left || r.bottom <= r.top) return FALSE;
    *gr = r; *pa = a; *pb = b;
    return TRUE;
}

extern "C" BOOL APIENTRY CerfDrvGradientFill(SURFOBJ* pso, CLIPOBJ* pco,
                                              XLATEOBJ* ,
                                              TRIVERTEX* pVertex, ULONG nVertex,
                                              PVOID pMesh, ULONG nMesh,
                                              RECTL* ,
                                              POINTL* , ULONG ulMode) {
    if (!pso || !pVertex || !pMesh) {
        CERF_LOG("cerf_guest: DrvGradientFill reject - null surface, vertex or mesh");
        return FALSE;
    }
    const ULONG op = ulMode & GRADIENT_FILL_OP_FLAG;

    if (op != GRADIENT_FILL_RECT_H && op != GRADIENT_FILL_RECT_V) {
        CERF_LOG_X("cerf_guest: DrvGradientFill reject - unsupported op", op);
        return FALSE;
    }
    const bool horiz = (op == GRADIENT_FILL_RECT_H);
    const GRADIENT_RECT* mesh = (const GRADIENT_RECT*)pMesh;

    int W, H, dst_stride, dst_bits;
    if (pso->dhsurf) {
        GPESurf* ds = (GPESurf*)pso->dhsurf;
        W = ds->Width(); H = ds->Height();
        dst_stride = (int)ds->Stride(); dst_bits = CerfFormatBpp(ds->Format());
    } else {
        W = (int)pso->sizlBitmap.cx; H = (int)pso->sizlBitmap.cy;
        dst_stride = (int)pso->lDelta;
        dst_bits   = CerfFormatBpp(CerfIFormatToEGPE(pso->iBitmapFormat));
    }

    int ext_lo = H, ext_hi = 0;
    for (ULONG i = 0; i < nMesh; ++i) {
        RECTL gr; const TRIVERTEX *a, *b;
        if (!CerfGradMeshRect(&mesh[i], pVertex, nVertex, horiz, &gr, &a, &b)) continue;
        if (gr.top    < ext_lo) ext_lo = gr.top;
        if (gr.bottom > ext_hi) ext_hi = gr.bottom;
    }
    if (ext_lo < 0) ext_lo = 0;
    if (ext_hi > H) ext_hi = H;
    if (ext_hi <= ext_lo) return TRUE;

    const ULONG budget = CerfVirt::kDmaPartitionSize - CerfVirt::kDmaPartHdrSize
                         - (ULONG)sizeof(CerfVirt::CerfGradDescriptor) - 64u;
    BOOL ok = TRUE;
    int yb0 = ext_lo;
    while (yb0 < ext_hi) {
        int yb1 = ext_hi;
        while (yb1 > yb0 + 1 &&
               CerfSpanBytes(0, yb0, W, yb1, dst_stride, dst_bits) > budget)
            yb1 = yb0 + (yb1 - yb0) / 2;

        if (!CerfArenaEnter()) CERF_FATAL("cerf_guest: DMA arena unavailable - halting");
        ULONG desc_off = 0u;
        CerfVirt::CerfGradDescriptor* pg = (CerfVirt::CerfGradDescriptor*)
            CerfArenaAlloc((ULONG)sizeof(CerfVirt::CerfGradDescriptor), &desc_off);
        if (!pg) CERF_FATAL("cerf_guest: DMA arena gradient alloc failed - halting");
        CerfVirt::CerfGradDescriptor& g = *pg;
        CerfStageWb dstwb = {0};
        memset(&g, 0, sizeof(g));
        g.magic = CerfVirt::kCerfGradMagic;
        g.axis  = horiz ? CerfVirt::kCerfGradAxisH : CerfVirt::kCerfGradAxisV;
        g.band_y_first = (uint32_t)yb0;
        g.band_y_count = (uint32_t)(yb1 - yb0);
        CerfFillSurfaceFromSurfobj(&g.dst, pso, yb0, yb1, &dstwb);

        for (ULONG i = 0; i < nMesh; ++i) {
            RECTL gr; const TRIVERTEX *a, *b;
            if (!CerfGradMeshRect(&mesh[i], pVertex, nVertex, horiz, &gr, &a, &b))
                continue;
            if (gr.bottom <= yb0 || gr.top >= yb1) continue;
            g.start_coord = horiz ? gr.left : gr.top;
            g.end_coord   = horiz ? gr.right : gr.bottom;
            g.start_color[0] = a->Red; g.start_color[1] = a->Green;
            g.start_color[2] = a->Blue; g.start_color[3] = a->Alpha;
            g.end_color[0]   = b->Red; g.end_color[1]   = b->Green;
            g.end_color[2]   = b->Blue; g.end_color[3]   = b->Alpha;
            if (!CerfEmitGradient(g, desc_off, gr, pco, W, H)) ok = FALSE;
        }
        if (dstwb.active)
            memcpy((void*)(ULONG_PTR)dstwb.dst_va, dstwb.arena_ptr, dstwb.span);
        CerfArenaLeave();
        yb0 = yb1;
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
