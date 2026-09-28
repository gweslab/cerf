#include "cerf_ddgpe.h"
#include "cerf_dma_arena.h"
#include "main.h"

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"

static void CerfLineYExtent(const GPELineParms* p, int* ymin, int* ymax) {
    static const signed char kDirDy[8][2] = {
        { 0,  1 }, { 1,  0 }, { 1,  0 }, { 0,  1 },
        { 0, -1 }, { -1, 0 }, { -1, 0 }, { 0, -1 },
    };
    const int maj_dy = kDirDy[p->iDir & 7][0];
    const int min_dy = kDirDy[p->iDir & 7][1];
    long accum = (long)p->dN + p->llGamma;
    const long axstp = (long)p->dN;
    const long dgstp = (long)p->dN - (long)p->dM;
    int y = p->yStart, lo = y, hi = y, n;
    for (n = p->cPels; n > 0; --n) {
        if (y < lo) lo = y;
        if (y > hi) hi = y;
        if (n == 1) break;
        y += maj_dy;
        if (axstp) {
            if (accum < 0) accum += axstp;
            else { y += min_dy; accum += dgstp; }
        }
    }
    *ymin = lo; *ymax = hi;
}

SCODE CerfDDGPE::HostLine(GPELineParms* p) {
    if (!p || !p->pDst) CERF_FATAL("cerf_guest: HostLine has no dst - halting");
    ULONG pa;
    const EGPEFormat df = p->pDst->Format();
    if ((!SurfaceFbPa(p->pDst, &pa) && !p->pDst->Buffer()) ||
        (df != gpe1Bpp && df != gpe2Bpp && df != gpe4Bpp &&
         df != gpe8Bpp && df != gpe16Bpp && df != gpe24Bpp && df != gpe32Bpp)) {
        CERF_LOG_X("cerf_guest: HostLine unsupported dst fmt", (ULONG)df);
        CERF_FATAL("cerf_guest: HostLine dst has no hardware route - halting");
    }
    const bool dst_fb = SurfaceFbPa(p->pDst, &pa) ? true : false;

    int ymin = 0, ymax = -1;
    if (!dst_fb) {
        CerfLineYExtent(p, &ymin, &ymax);
        const int H = (int)p->pDst->Height();
        if (ymin < 0) ymin = 0;
        if (ymax > H - 1) ymax = H - 1;
        if (ymax < ymin) return S_OK;
    }

    const int   W          = (int)p->pDst->Width();
    const int   dst_stride = (int)p->pDst->Stride();
    const int   dst_bits   = CerfFormatBpp(df);
    const ULONG budget = CerfVirt::kDmaPartitionSize - CerfVirt::kDmaPartHdrSize
                         - (ULONG)sizeof(CerfVirt::CerfLineDescriptor) - 64u;

    int yb0 = ymin;
    for (;;) {
        int yb1 = dst_fb ? 0 : (ymax + 1);
        if (!dst_fb) {
            while (yb1 > yb0 + 1 &&
                   CerfSpanBytes(0, yb0, W, yb1, dst_stride, dst_bits) > budget)
                yb1 = yb0 + (yb1 - yb0) / 2;
        }

        if (!CerfArenaEnter()) CERF_FATAL("cerf_guest: DMA arena unavailable - halting");
        ULONG desc_off = 0u;
        CerfVirt::CerfLineDescriptor* pd = (CerfVirt::CerfLineDescriptor*)
            CerfArenaAlloc((ULONG)sizeof(CerfVirt::CerfLineDescriptor), &desc_off);
        if (!pd) CERF_FATAL("cerf_guest: DMA arena line alloc failed - halting");
        CerfVirt::CerfLineDescriptor& d = *pd;
        memset(&d, 0, sizeof(d));
        d.magic       = CerfVirt::kCerfLineMagic;
        d.x_start     = p->xStart;
        d.y_start     = p->yStart;
        d.c_pels      = p->cPels;
        d.d_m         = p->dM;
        d.d_n         = p->dN;
        d.ll_gamma    = p->llGamma;
        d.i_dir       = p->iDir;
        d.style       = p->style;
        d.style_state = p->styleState;
        d.solid_color = (uint32_t)p->solidColor;
        d.mix         = p->mix;
        RECTL lclip;
        CerfEffectiveClip(&lclip, p->prclClip, p->pDst);
        d.has_clip = 1u;
        RectToDesc(&d.clip_rect, &lclip);
        CerfStageWb dstwb = {0};
        if (dst_fb) {
            d.band_y_first = 0u;
            d.band_y_count = 0u;
            FillSurface(&d.dst, p->pDst, 0, 0, W, (int)p->pDst->Height(),
                        true, false, &dstwb);
        } else {
            d.band_y_first = (uint32_t)yb0;
            d.band_y_count = (uint32_t)(yb1 - yb0);
            FillSurface(&d.dst, p->pDst, 0, yb0, W, yb1, true, false, &dstwb);
        }
        const ULONG cgl = CerfGpeLine(desc_off);
        if (cgl == 2u && dstwb.active)
            memcpy((void*)(ULONG_PTR)dstwb.dst_va, dstwb.arena_ptr, dstwb.span);
        CerfArenaLeave();
        if (cgl != 2u) CERF_FATAL("cerf_guest: host line did not complete - halting");

        if (dst_fb) break;
        yb0 = yb1;
        if (yb0 > ymax) break;
    }
    return S_OK;
}
