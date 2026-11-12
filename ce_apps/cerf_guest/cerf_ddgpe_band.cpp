#include "cerf_ddgpe.h"

int CerfBrushRowAt(const CerfBltBand& b, int row) {
    return (int)((ULONG)(b.brush_t + b.dt + row) % (ULONG)b.bh);
}

void CerfBrushBandRows(const CerfBltBand& b, int r0, int r1, int* by0, int* by1) {
    const int count = r1 - r0;
    if (count >= b.bh) { *by0 = 0; *by1 = b.bh; return; }
    *by0 = CerfBrushRowAt(b, r0);
    *by1 = *by0 + count;
}

int CerfBrushClampEnd(const CerfBltBand& b, int r0, int r1) {
    if (!b.has_brush || !b.brush_banded) return r1;
    const int allowed = b.bh - CerfBrushRowAt(b, r0);
    if (r1 - r0 > allowed) r1 = r0 + allowed;
    const int wrap = -(b.brush_t + b.dt);
    if (wrap > r0 && wrap < r1) r1 = wrap;
    return r1;
}

int CerfBrushClampStart(const CerfBltBand& b, int r0, int r1) {
    if (!b.has_brush || !b.brush_banded) return r0;
    const int lo = r1 - 1 - CerfBrushRowAt(b, r1 - 1);
    return (r0 < lo) ? lo : r0;
}

int CerfBrushIndent(const CerfBltBand& b, const GPEBltParms* p) {
    return p->pptlBrush ? (b.bw - (int)p->pptlBrush->x) : 0;
}

static int CerfBrushColAt(const CerfBltBand& b, int lind, int x) {
    return (int)((ULONG)(lind + x) % (ULONG)b.bw);
}

void CerfBrushBandCols(const CerfBltBand& b, int lind, int x0, int x1, int* bx0, int* bx1) {
    const int count = x1 - x0;
    if (count >= b.bw) { *bx0 = 0; *bx1 = b.bw; return; }
    *bx0 = CerfBrushColAt(b, lind, x0);
    *bx1 = *bx0 + count;
}

int CerfBrushColClampEnd(const CerfBltBand& b, int lind, int x0, int x1) {
    if (!b.has_brush || !b.brush_banded) return x1;
    const int allowed = b.bw - CerfBrushColAt(b, lind, x0);
    if (x1 - x0 > allowed) x1 = x0 + allowed;
    const int wrap = -lind;
    if (wrap > x0 && wrap < x1) x1 = wrap;
    return x1;
}

int CerfBrushColClampStart(const CerfBltBand& b, int lind, int x0, int x1) {
    if (!b.has_brush || !b.brush_banded) return x0;
    const int lo = x1 - 1 - CerfBrushColAt(b, lind, x1 - 1);
    return (x0 < lo) ? lo : x0;
}

ULONG CerfBandColSpanBytes(const CerfBltBand& b, int lind, int x0, int x1, int r0, int r1) {
    ULONG t = 0;
    const int c0 = x0 - b.dl, c1 = x1 - b.dl;
    if (!b.dst_fb)
        t += CerfSpanBytes(x0, b.dt + r0, x1, b.dt + r1, b.dst_stride, b.dst_bits);
    if (b.has_src && !b.src_fb) {
        const int sw  = b.sr - b.sl;
        const int sx0 = b.use_lut_y ? CerfSrcDyAt(b.width, sw, c0) : c0;
        const int sx1 = b.use_lut_y ? CerfSrcDyAt(b.width, sw, c1 - 1) : (c1 - 1);
        const int sy0 = b.use_lut_y ? CerfSrcDyAt(b.height, b.src_h, r0) : r0;
        const int sy1 = b.use_lut_y ? CerfSrcDyAt(b.height, b.src_h, r1 - 1) : (r1 - 1);
        t += CerfSpanBytes(b.sl + sx0, b.st + sy0, b.sl + sx1 + 1, b.st + sy1 + 1,
                           b.src_stride, b.src_bits);
    }
    if (b.has_mask)
        t += CerfSpanBytes(b.ml + c0, b.mt + r0, b.ml + c1, b.mt + r1,
                           b.mask_stride, b.mask_bits);
    if (b.has_brush && b.brush_banded) {
        int by0 = 0, by1 = 0, bx0 = 0, bx1 = 0;
        CerfBrushBandRows(b, r0, r1, &by0, &by1);
        CerfBrushBandCols(b, lind, x0, x1, &bx0, &bx1);
        t += CerfSpanBytes(bx0, by0, bx1, by1, b.brush_stride, b.brush_bits);
    }
    return t;
}

int CerfColBandEnd(const CerfBltBand& b, int lind, ULONG budget, int r0, int r1, int x0,
                   int cr) {
    int x1 = CerfBrushColClampEnd(b, lind, x0, cr);
    while (x1 > x0 + 1) {
        if (CerfBandColSpanBytes(b, lind, x0, x1, r0, r1) <= budget) break;
        x1 = x0 + (x1 - x0) / 2;
    }
    return x1;
}

int CerfColBandStart(const CerfBltBand& b, int lind, ULONG budget, int r0, int r1, int cl,
                     int x1) {
    int x0 = CerfBrushColClampStart(b, lind, cl, x1);
    while (x0 < x1 - 1) {
        if (CerfBandColSpanBytes(b, lind, x0, x1, r0, r1) <= budget) break;
        x0 = x1 - (x1 - x0) / 2;
    }
    return x0;
}

int CerfRowSplitEnd(int x0, int x1, int y0, int y1, int stride, int bits, ULONG budget) {
    while (x1 > x0 + 1 && CerfSpanBytes(x0, y0, x1, y1, stride, bits) > budget)
        x1 = x0 + (x1 - x0) / 2;
    return x1;
}

bool CerfBandClip(const CerfBltBand& b, GPEBltParms* p, int* cl, int* cr) {
    RECTL bclip;
    CerfEffectiveClip(&bclip, p->prclClip, p->pDst);
    int l = b.dl, r = b.dl + b.width, t = b.dt, bo = b.dt + b.height;
    CerfClampWindow(&l, &t, &r, &bo, &bclip);
    *cl = l;
    *cr = r;
    return r > l && bo > t;
}

ULONG CerfBandSpanBytes(const CerfBltBand& b, int cl, int cr, int r0, int r1) {
    ULONG t = 0;
    if (!b.dst_fb)
        t += CerfSpanBytes(cl, b.dt + r0, cr, b.dt + r1, b.dst_stride, b.dst_bits);
    if (b.has_src && !b.src_fb) {
        const int sy0 = b.use_lut_y ? CerfSrcDyAt(b.height, b.src_h, r0) : r0;
        const int sy1 = b.use_lut_y ? CerfSrcDyAt(b.height, b.src_h, r1 - 1) : (r1 - 1);
        t += CerfSpanBytes(b.sl, b.st + sy0, b.sr, b.st + sy1 + 1,
                           b.src_stride, b.src_bits);
    }
    if (b.has_mask)
        t += CerfSpanBytes(b.ml, b.mt + r0, b.mr, b.mt + r1,
                           b.mask_stride, b.mask_bits);
    if (b.has_brush && b.brush_banded) {
        int by0 = 0, by1 = 0;
        CerfBrushBandRows(b, r0, r1, &by0, &by1);
        t += CerfSpanBytes(0, by0, b.bw, by1, b.brush_stride, b.brush_bits);
    }
    return t;
}

int CerfBandEnd(const CerfBltBand& b, int cl, int cr, ULONG budget, int r0) {
    int r1 = CerfBrushClampEnd(b, r0, b.height);
    while (r1 > r0 + 1) {
        if (CerfBandSpanBytes(b, cl, cr, r0, r1) <= budget) break;
        r1 = r0 + (r1 - r0) / 2;
    }
    return r1;
}

int CerfBandStart(const CerfBltBand& b, int cl, int cr, ULONG budget, int r1) {
    int r0 = CerfBrushClampStart(b, 0, r1);
    while (r0 < r1 - 1) {
        if (CerfBandSpanBytes(b, cl, cr, r0, r1) <= budget) break;
        r0 = r1 - (r1 - r0) / 2;
    }
    return r0;
}

void CerfDDGPE::EmitBltRow(const CerfBltBand& b, GPEBltParms* p, ULONG budget, int r0,
                           int r1, int cl, int cr) {
    if (r1 - r0 > 1 || CerfBandSpanBytes(b, cl, cr, r0, r1) <= budget) {
        EmitBltBand(b, p, r0, r1, cl, cr, false);
        return;
    }
    const int  lind     = CerfBrushIndent(b, p);
    const bool leftward = BltAliasKind(p) == kCerfAliasGrid && !p->xPositive;
    int x0 = cl, x1 = cr;
    for (int i = 0; i < cr - cl; ++i) {
        if (x1 <= x0) break;
        if (leftward) {
            const int s = CerfColBandStart(b, lind, budget, r0, r1, x0, x1);
            EmitBltBand(b, p, r0, r1, s, x1, true);
            x1 = s;
        } else {
            const int e = CerfColBandEnd(b, lind, budget, r0, r1, x0, x1);
            EmitBltBand(b, p, r0, r1, x0, e, true);
            x0 = e;
        }
    }
}

void CerfDDGPE::EmitBltBandsUp(const CerfBltBand& b, GPEBltParms* p,
                               ULONG budget, int cl, int cr) {
    int r1 = b.height;
    for (int i = 0; i < b.height; ++i) {
        if (r1 <= 0) break;
        int r0 = CerfBandStart(b, cl, cr, budget, r1);
        EmitBltRow(b, p, budget, r0, r1, cl, cr);
        r1 = r0;
    }
}

void CerfDDGPE::EmitBltBandsDown(const CerfBltBand& b, GPEBltParms* p,
                                 ULONG budget, int cl, int cr) {
    int r0 = 0;
    for (int i = 0; i < b.height; ++i) {
        if (r0 >= b.height) break;
        int r1 = CerfBandEnd(b, cl, cr, budget, r0);
        EmitBltRow(b, p, budget, r0, r1, cl, cr);
        r0 = r1;
    }
}

void CerfDDGPE::EmitBltBands(const CerfBltBand& b, GPEBltParms* p, ULONG budget,
                             CerfBandOrder order) {
    int cl = 0, cr = 0;
    if (!CerfBandClip(b, p, &cl, &cr)) return;
    if (order == kCerfBandUp) EmitBltBandsUp(b, p, budget, cl, cr);
    else                      EmitBltBandsDown(b, p, budget, cl, cr);
}
