#include "cerf_ddgpe.h"
#include "cerf_dma_arena.h"
#include "main.h"

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"

static void CerfSpan(int x0, int y0, int x1, int y1, int stride, int bits,
                     LONG* lo_off, ULONG* span) {
    const LONG row_lo = ((LONG)x0 * (LONG)bits) / 8;
    const LONG row_hi = (((LONG)x1 * (LONG)bits) + 7) / 8 - 1;
    const LONG first  = (LONG)y0       * (LONG)stride;
    const LONG last   = (LONG)(y1 - 1) * (LONG)stride;
    *lo_off = ((first < last) ? first : last) + row_lo;
    *span   = (ULONG)((((first < last) ? last : first) + row_hi) - *lo_off + 1);
}

ULONG CerfSpanBytes(int x0, int y0, int x1, int y1, int stride, int bits) {
    LONG lo; ULONG sp;
    CerfSpan(x0, y0, x1, y1, stride, bits, &lo, &sp);
    return sp;
}

int CerfSrcDyAt(int dst_len, int src_len, int k) {
    int src_pos = 0, c;
    if (dst_len == src_len) return k;
    if (dst_len > src_len) {
        const int d_minor = 2 * src_len, d_major = 2 * src_len - 2 * dst_len;
        int accum = 3 * src_len - 2 * dst_len;
        for (c = 0; c < dst_len; ++c) {
            if (c == k) return src_pos;
            if (accum < 0) accum += d_minor;
            else { accum += d_major; ++src_pos; }
        }
    } else {
        const int d_minor = 2 * dst_len, d_major = 2 * dst_len - 2 * src_len;
        int accum = 2 * dst_len - src_len;
        while (accum < 0) { accum += d_minor; ++src_pos; }
        accum += d_major;
        for (c = 0; c < dst_len; ++c) {
            if (c == k) return src_pos;
            ++src_pos;
            while (accum < 0) { ++src_pos; accum += d_minor; }
            accum += d_major;
        }
    }
    return src_pos;
}

static void CerfWindowHalt(const char* what, int x0, int y0, int x1, int y1,
                           int w, int h) {
    CERF_LOG_X("cerf_guest: stage window x0", (ULONG)x0);
    CERF_LOG_X("cerf_guest: stage window y0", (ULONG)y0);
    CERF_LOG_X("cerf_guest: stage window x1", (ULONG)x1);
    CERF_LOG_X("cerf_guest: stage window y1", (ULONG)y1);
    CERF_LOG_X("cerf_guest: surface width", (ULONG)w);
    CERF_LOG_X("cerf_guest: surface height", (ULONG)h);
    CERF_FATAL(what);
}

void CerfClampWindow(int* x0, int* y0, int* x1, int* y1,
                     const RECTL* bound) {
    RECTL r;
    r.left = *x0; r.top = *y0; r.right = *x1; r.bottom = *y1;
    CerfRectClamp(&r, bound);
    *x0 = (int)r.left; *y0 = (int)r.top;
    *x1 = (int)r.right; *y1 = (int)r.bottom;
}

static void CerfNarrowToSrc(int* x0, int* y0, int* x1, int* y1, GPESurf* s) {
    const int w = (int)s->Width(), h = (int)s->Height();
    if (w <= 0 || h <= 0)
        CerfWindowHalt("cerf_guest: source surface reports no extent - halting",
                       *x0, *y0, *x1, *y1, w, h);
    RECTL bound;
    bound.left = 0; bound.top = 0; bound.right = w; bound.bottom = h;
    CerfClampWindow(x0, y0, x1, y1, &bound);
    if (*x1 <= *x0 || *y1 <= *y0)
        CerfWindowHalt("cerf_guest: source window outside source surface - halting",
                       *x0, *y0, *x1, *y1, w, h);
}

static void CerfNarrowToMask(int* x0, int* y0, int* x1, int* y1, GPESurf* s,
                             const RECTL* mrect) {
    const int w = (int)s->Width(), h = (int)s->Height();
    RECTL bound = *mrect;
    if (bound.right < bound.left) {
        const LONG t = bound.right; bound.right = bound.left; bound.left = t;
    }
    if (bound.bottom < bound.top) {
        const LONG t = bound.bottom; bound.bottom = bound.top; bound.top = t;
    }
    if (w > 0 && h > 0) {
        RECTL extent;
        extent.left = 0; extent.top = 0; extent.right = w; extent.bottom = h;
        CerfRectClamp(&bound, &extent);
    }
    CerfClampWindow(x0, y0, x1, y1, &bound);
    if (*x1 <= *x0 || *y1 <= *y0)
        CerfWindowHalt("cerf_guest: mask window outside mask bounds - halting",
                       *x0, *y0, *x1, *y1, w, h);
}

static void CerfStageSurface(CerfVirt::CerfBltSurface* s, ULONG buffer_va,
                             int x0, int y0, int x1, int y1,
                             int stride, int bits, CerfStageWb* wb) {
    LONG  lo_off;
    ULONG span;
    if (stride == 0 || bits <= 0 || x1 <= x0 || y1 <= y0) {
        CERF_LOG_X("cerf_guest: Stage BAD GEOMETRY x0", (ULONG)x0);
        CERF_LOG_X("cerf_guest: Stage BAD GEOMETRY y0", (ULONG)y0);
        CERF_LOG_X("cerf_guest: Stage BAD GEOMETRY x1", (ULONG)x1);
        CERF_LOG_X("cerf_guest: Stage BAD GEOMETRY y1", (ULONG)y1);
        CERF_LOG_X("cerf_guest: Stage BAD GEOMETRY stride", (ULONG)stride);
        CERF_LOG_X("cerf_guest: Stage BAD GEOMETRY bits", (ULONG)bits);
        CERF_FATAL("cerf_guest: Stage BAD GEOMETRY - halting");
    }

    CerfSpan(x0, y0, x1, y1, stride, bits, &lo_off, &span);

    ULONG arena_off = 0u;
    void* dstp = CerfArenaAlloc(span, &arena_off);
    if (!dstp) {
        CERF_LOG_X("cerf_guest: Stage arena alloc failed, span", span);
        CERF_FATAL("cerf_guest: DMA arena surface alloc failed - halting");
    }
    memcpy(dstp, (const void*)(ULONG_PTR)((LONG)buffer_va + lo_off), span);

    s->buffer    = (uint32_t)((LONG)arena_off - lo_off);
    s->stage_off = arena_off;
    s->stage_len = span;
    s->is_fb_pa  = 0u;

    if (wb) {
        wb->active    = TRUE;
        wb->dst_va    = (ULONG)((LONG)buffer_va + lo_off);
        wb->arena_ptr = dstp;
        wb->span      = span;
    }
}

SCODE CerfDDGPE::BltPrepare(GPEBltParms* p) {
    ULONG pa;
    const bool dstHw = p->pDst && CerfConvertibleFmt(p->pDst->Format()) &&
                       (SurfaceFbPa(p->pDst, &pa) || p->pDst->Buffer() != NULL);
    const bool srcFb = p->pSrc && SurfaceFbPa(p->pSrc, &pa);
    if (!dstHw && !srcFb) {
        CERF_LOG_X("cerf_guest: BltPrepare no HW route, dst fmt",
                   (ULONG)(p->pDst ? p->pDst->Format() : 0));
        CERF_FATAL("cerf_guest: BltPrepare has no hardware route - halting");
    }
    if (BltAliasKind(p) == kCerfAliasGrid) {
        p->xPositive = (p->prclSrc->left >= p->prclDst->left) ? 1 : 0;
        p->yPositive = (p->prclSrc->top  >= p->prclDst->top)  ? 1 : 0;
    }
    p->pBlt = (SCODE (GPE::*)(GPEBltParms*))&CerfDDGPE::HwBlt;
    return S_OK;
}

void CerfDDGPE::RectToDesc(CerfVirt::CerfBltRect* r, const RECTL* s) {
    r->left = s->left; r->top = s->top; r->right = s->right; r->bottom = s->bottom;
}

void CerfDDGPE::FillSurface(CerfVirt::CerfBltSurface* s, GPESurf* surf,
                            int x0, int y0, int x1, int y1, bool host_writes,
                            bool read_palette, CerfStageWb* wb) {
    ULONG pa;
    (void)host_writes;
    s->format = (uint32_t)surf->Format();
    s->stride = (int32_t)surf->Stride();
    if (x1 < x0) { const int t = x0; x0 = x1; x1 = t; }
    if (y1 < y0) { const int t = y0; y0 = y1; y1 = t; }
    if (SurfaceFbPa(surf, &pa)) { s->buffer = pa; s->is_fb_pa = 1u; }
    else {
        CerfStageSurface(s, (ULONG)(ULONG_PTR)surf->Buffer(),
                         x0, y0, x1, y1, surf->Stride(),
                         CerfFormatBpp(surf->Format()), wb);
    }
    GPEFormat* gf = read_palette ? surf->FormatPtr() : NULL;
    s->pal_entries = gf ? (uint32_t)gf->m_PaletteEntries : 0u;
    if (gf && gf->m_pPalette && (gf->m_PaletteEntries == 3 || gf->m_PaletteEntries == 4)) {
        for (int i = 0; i < gf->m_PaletteEntries; ++i) s->mask[i] = gf->m_pPalette[i];
    }
    if (surf->IsRotate()) {
        s->is_rotate = 1u;
        switch (surf->Rotate()) {
            case DMDO_90:  s->rotate = CerfVirt::kCerfRotate90;  break;
            case DMDO_180: s->rotate = CerfVirt::kCerfRotate180; break;
            case DMDO_270: s->rotate = CerfVirt::kCerfRotate270; break;
            default:       s->rotate = CerfVirt::kCerfRotate0;   break;
        }
        s->screen_w = (uint32_t)surf->ScreenWidth();
        s->screen_h = (uint32_t)surf->ScreenHeight();
    }
}

void CerfDDGPE::FillSurfaceFromSurfobj(CerfVirt::CerfBltSurface* s, SURFOBJ* pso,
                                      int y0, int y1, CerfStageWb* wb) {
    if (!pso) return;
    if (pso->dhsurf) {
        GPESurf* ds = (GPESurf*)pso->dhsurf;
        FillSurface(s, ds, 0, y0, ds->Width(), y1, true, true, wb);
        return;
    }
    s->format = (uint32_t)CerfIFormatToEGPE(pso->iBitmapFormat);
    s->stride = (int32_t)pso->lDelta;
    CerfStageSurface(s, (ULONG)(ULONG_PTR)pso->pvScan0,
                     0, y0, (int)pso->sizlBitmap.cx, y1,
                     (int)pso->lDelta, CerfFormatBpp((EGPEFormat)s->format), wb);
}

void CerfDDGPE::EmitBltBand(const CerfBltBand& b, GPEBltParms* p, int r0, int r1) {
    RECTL eclip;
    CerfEffectiveClip(&eclip, p->prclClip, p->pDst);
    int dw = b.dr - b.dl; if (dw < 0) dw = -dw;
    int vx0 = b.dl, vx1 = b.dl + dw;
    int vy0 = b.dt + r0, vy1 = b.dt + r1;
    CerfClampWindow(&vx0, &vy0, &vx1, &vy1, &eclip);
    if (vx1 <= vx0 || vy1 <= vy0) return;
    const int c0  = vx0 - b.dl,  c1  = vx1 - b.dl;
    const int rr0 = vy0 - b.dt,  rr1 = vy1 - b.dt;
    const int sw = b.sr - b.sl;
    const int sx0 = b.use_lut_y ? CerfSrcDyAt(dw, sw, c0) : c0;
    const int sx1 = b.use_lut_y ? CerfSrcDyAt(dw, sw, c1 - 1) : (c1 - 1);
    const int sy0 = b.use_lut_y ? CerfSrcDyAt(b.height, b.src_h, rr0) : rr0;
    const int sy1 = b.use_lut_y ? CerfSrcDyAt(b.height, b.src_h, rr1 - 1) : (rr1 - 1);

    if (!CerfArenaEnter()) CERF_FATAL("cerf_guest: DMA arena unavailable - halting");
    ULONG desc_off = 0u;
    CerfVirt::CerfBltDescriptor* pd = (CerfVirt::CerfBltDescriptor*)
        CerfArenaAlloc((ULONG)sizeof(CerfVirt::CerfBltDescriptor), &desc_off);
    if (!pd) CERF_FATAL("cerf_guest: DMA arena descriptor alloc failed - halting");
    CerfVirt::CerfBltDescriptor& d = *pd;
    memset(&d, 0, sizeof(d));
    d.magic          = CerfVirt::kCerfBltMagic;
    d.rop4           = (uint32_t)p->rop4;
    d.blt_flags      = (uint32_t)p->bltFlags;
    d.solid_color    = (uint32_t)p->solidColor;
    d.i_mode         = (uint32_t)p->iMode;
    d.x_positive     = p->xPositive ? 1u : 0u;
    d.y_positive     = p->yPositive ? 1u : 0u;
    d.blend_function = *(const ULONG*)&p->blendFunction;
    d.band_row_first = (uint32_t)rr0;
    d.band_row_count = (uint32_t)(rr1 - rr0);

    CerfStageWb dstwb = {0};
    RectToDesc(&d.dst_rect, p->prclDst);
    FillSurface(&d.dst, p->pDst, vx0, vy0, vx1, vy1, true, true, &dstwb);

    if (b.has_src) {
        d.has_src        = 1u;
        d.convert_active = (!b.src_pal && p->pConvert != NULL) ? 1u : 0u;
        if (b.src_pal && p->pLookup) {
            const ULONG entries = 1u << CerfFormatBpp(p->pSrc->Format());
            ULONG  lut_off = 0u;
            ULONG* lut = (ULONG*)CerfArenaAlloc(entries * (ULONG)sizeof(ULONG),
                                                &lut_off);
            if (!lut) CERF_FATAL("cerf_guest: DMA arena lookup alloc failed - halting");
            memcpy(lut, p->pLookup, entries * sizeof(ULONG));
            d.lookup_off = lut_off;
            d.has_lookup = 1u;
        }
        d.to_mono = p->toMono ? 1u : 0u;
        d.mono_bg = (uint32_t)p->monoBg;
        RectToDesc(&d.src_rect, p->prclSrc);
        int sxa = b.sl + sx0,     sya = b.st + sy0;
        int sxb = b.sl + sx1 + 1, syb = b.st + sy1 + 1;
        CerfNarrowToSrc(&sxa, &sya, &sxb, &syb, p->pSrc);
        FillSurface(&d.src, p->pSrc, sxa, sya, sxb, syb, false);
    }
    if (b.has_mask) {
        d.has_mask = 1u;
        RectToDesc(&d.mask_rect, p->prclMask);
        int mxa = b.ml + c0,   mya = b.mt + rr0;
        int mxb = b.ml + c1,   myb = b.mt + rr1;
        CerfNarrowToMask(&mxa, &mya, &mxb, &myb, p->pMask, p->prclMask);
        FillSurface(&d.mask, p->pMask, mxa, mya, mxb, myb, false);
    }
    if (b.has_brush) {
        d.has_brush    = 1u;
        d.brush_width  = (uint32_t)p->pBrush->Width();
        d.brush_height = (uint32_t)p->pBrush->Height();
        int by0 = 0, by1 = b.bh;
        if (b.brush_banded) CerfBrushBandRows(b, rr0, rr1, &by0, &by1);
        FillSurface(&d.brush, p->pBrush, 0, by0, b.bw, by1, false, false);
        if (p->pptlBrush) {
            d.brush_has_ptl = 1u;
            d.brush_ptl_x   = p->pptlBrush->x;
            d.brush_ptl_y   = p->pptlBrush->y;
        }
    }
    d.has_clip = 1u;
    RectToDesc(&d.clip_rect, &eclip);

    const ULONG cgb = CerfGpeBlt(desc_off);
    if (cgb == 2u && dstwb.active)
        memcpy((void*)(ULONG_PTR)dstwb.dst_va, dstwb.arena_ptr, dstwb.span);
    CerfArenaLeave();
    if (cgb != 2u) CERF_FATAL("cerf_guest: host blit did not complete - halting");
}

// Fun fact: touching this shit will cause INTERNAL COMPILER ERROR for mips1 with a 90% chance.
// It was not a fun fact. There is nothing fun in fixing "ICE". 
// This driver works on god's support and cosmical/alien energy. 
SCODE CerfDDGPE::HwBlt(GPEBltParms* p) {
    ULONG pa;
    if (!p->pDst || !p->prclDst || !CerfConvertibleFmt(p->pDst->Format())) {
        CERF_LOG_X("cerf_guest: HwBlt unsupported dst fmt",
                   (ULONG)(p->pDst ? p->pDst->Format() : 0));
        CERF_FATAL("cerf_guest: HwBlt dst has no hardware route - halting");
    }
    const bool dst_fb = SurfaceFbPa(p->pDst, &pa) ? true : false;
    if (!dst_fb && !p->pDst->Buffer())
        CERF_FATAL("cerf_guest: HwBlt dst has no buffer - halting");

    const bool has_src = (p->pSrc != NULL && p->prclSrc != NULL);
    bool src_fb = false, src_pal = false;
    if (has_src) {
        src_pal = (CerfFormatBpp(p->pSrc->Format()) <= 8) ? true : false;
        if (!src_pal && !CerfConvertibleFmt(p->pSrc->Format())) {
            CERF_LOG_X("cerf_guest: HwBlt unsupported src fmt", (ULONG)p->pSrc->Format());
            CERF_FATAL("cerf_guest: HwBlt src has no hardware route - halting");
        }
        src_fb = SurfaceFbPa(p->pSrc, &pa) ? true : false;
        if (!src_fb && !p->pSrc->Buffer())
            CERF_FATAL("cerf_guest: HwBlt src has no buffer - halting");
    }
    const bool has_mask  = (p->pMask != NULL && p->prclMask != NULL &&
                            p->pMask->Buffer() != NULL);
    const bool has_brush = (p->pBrush != NULL);

    int height = p->prclDst->bottom - p->prclDst->top;
    int width  = p->prclDst->right  - p->prclDst->left;
    if (height < 0) height = -height;
    if (width  < 0) width  = -width;
    if (height <= 0 || width <= 0) return S_OK;

    GPESurf* const orig_src  = p->pSrc;
    RECTL*   const orig_rcl  = p->prclSrc;
    GPESurf* snap = NULL;
    CerfBandOrder order = kCerfBandDown;
    if (FAILED(PlanAliasedBlt(p, &order, &snap))) return E_OUTOFMEMORY;
    if (snap) {
        src_fb  = false;
        src_pal = (CerfFormatBpp(p->pSrc->Format()) <= 8) ? true : false;
    }

    const int dl = p->prclDst->left, dt = p->prclDst->top, dr = p->prclDst->right;
    const int dst_stride = (int)p->pDst->Stride();
    const int dst_bits   = CerfFormatBpp(p->pDst->Format());

    int sl = 0, st = 0, sr = 0, src_stride = 0, src_bits = 0, src_w = 0, src_h = 0;
    if (has_src) {
        sl = p->prclSrc->left; st = p->prclSrc->top; sr = p->prclSrc->right;
        src_stride = (int)p->pSrc->Stride();
        src_bits   = CerfFormatBpp(p->pSrc->Format());
        src_w = p->prclSrc->right  - p->prclSrc->left;
        src_h = p->prclSrc->bottom - p->prclSrc->top;
    }
    const bool stretch   = (p->bltFlags & 0x0008u) != 0u;
    const bool use_lut_y = has_src && stretch && (src_w != width || src_h != height);

    int ml = 0, mt = 0, mr = 0, mask_stride = 0, mask_bits = 0;
    if (has_mask) {
        ml = p->prclMask->left; mt = p->prclMask->top; mr = p->prclMask->right;
        mask_stride = (int)p->pMask->Stride();
        mask_bits   = CerfFormatBpp(p->pMask->Format());
    }

    ULONG lut_bytes = 0;
    if (has_src && src_pal && p->pLookup)
        lut_bytes = (1u << CerfFormatBpp(p->pSrc->Format())) * (ULONG)sizeof(ULONG);
    int bw = 0, bh = 0, brush_t = 0, brush_stride = 0, brush_bits = 0;
    bool brush_fb = false;
    if (has_brush) {
        bw = p->pBrush->Width();
        bh = p->pBrush->Height();
        CerfRequireExtent(bw, kCerfExtentBrushWidth);
        CerfRequireExtent(bh, kCerfExtentBrushHeight);
        brush_stride = (int)p->pBrush->Stride();
        brush_bits   = CerfFormatBpp(p->pBrush->Format());
        brush_fb     = SurfaceFbPa(p->pBrush, &pa) ? true : false;
        if (!brush_fb && !p->pBrush->Buffer())
            CERF_FATAL("cerf_guest: HwBlt brush has no buffer - halting");
        brush_t      = p->pptlBrush ? (bh - p->pptlBrush->y) : 0;
    }
    ULONG budget = CerfVirt::kDmaPartitionSize - CerfVirt::kDmaPartHdrSize
                   - (ULONG)sizeof(CerfVirt::CerfBltDescriptor)
                   - lut_bytes - 64u;

    bool brush_banded = false;
    if (has_brush && !brush_fb) {
        const ULONG brush_all = CerfSpanBytes(0, 0, bw, bh, brush_stride, brush_bits);
        if (brush_all <= budget / 2u) budget -= brush_all;
        else                          brush_banded = true;
    }

    const CerfBltBand band = { dl, dt, dr, sl, st, sr, ml, mt, mr,
                               height, width, src_h, bw, bh, brush_t,
                               dst_stride, dst_bits, src_stride, src_bits,
                               mask_stride, mask_bits, brush_stride, brush_bits,
                               has_src, has_mask, has_brush, src_pal, use_lut_y,
                               dst_fb, src_fb, brush_banded };

    EmitBltBands(band, p, budget, order);
    if (snap) {
        p->pSrc    = orig_src;
        p->prclSrc = orig_rcl;
        delete snap;
    }
    return S_OK;
}

extern "C" int CerfDDrawBlt(void* dstLcl, void* srcLcl, const RECTL* rDest,
                            const RECTL* rSrc, unsigned long ddFlags,
                            unsigned long ropArg, unsigned long fillColor,
                            unsigned long srcKeyOverride) {
    if (!dstLcl || !rDest) return 0;
    DDGPESurf* pDst = DDGPESurf::GetDDGPESurf((LPDDRAWI_DDRAWSURFACE_LCL)dstLcl);
    if (!pDst) return 0;
    DDGPESurf* pSrc = srcLcl
        ? DDGPESurf::GetDDGPESurf((LPDDRAWI_DDRAWSURFACE_LCL)srcLcl) : NULL;

    if (ddFlags & (0x2000u | 0x4000u)) return 0;

    ULONG solidColor = 0, rop4, bltFlags = 0;
    const RECT* prclSrc = NULL;
    if (ddFlags & 0x400u) {
        solidColor = fillColor;
        rop4 = 0xF0F0u;
        pSrc = NULL;
    } else {

        const ULONG ropByte = ((ddFlags & 0x20000u) && ropArg != 0u)
            ? ((ropArg >> 16) & 0xFFu) : 0xCCu;
        rop4 = (ropByte << 8) | ropByte;
        if (pSrc && rSrc) prclSrc = (const RECT*)rSrc;
        if (prclSrc &&
            ((rDest->right - rDest->left) != (rSrc->right - rSrc->left) ||
             (rDest->bottom - rDest->top) != (rSrc->bottom - rSrc->top)))
            bltFlags |= 8u;

        if ((ddFlags & 0x8000u) && pSrc) {
            bltFlags |= 4u;
            solidColor = pSrc->ColorKeyLow();
        } else if ((ddFlags & 0x10000u) && pSrc) {
            bltFlags |= 4u;
            solidColor = srcKeyOverride;
        }
    }
    SCODE sc = ((CerfDDGPE*)GetGPE())->BltExpanded(
        pDst, pSrc, NULL, (const RECT*)rDest, prclSrc, solidColor, bltFlags, (ROP4)rop4);
    return (sc == S_OK) ? 1 : 0;
}

