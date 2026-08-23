#pragma once

#include "../../core/service.h"

#include <cstdint>
#include <vector>

class StateWriter;
class StateReader;
struct Gpu2dGradwPaint;
class Imx51Gpu2dGradwSampler;

/* One FLUSH's fill target, decoded by the peripheral from the g12 register file
   (G2D_BASE0/CFG0/SCISSORX/Y + VGV1_SCISSORX/Y + VGV1_CFG1 + G2D_COLOR). */
struct Gpu2dFillTarget {
    uint32_t dest_pa;    /* G2D_BASE0 (tile-corner physical; gpuaddr==physical) */
    int32_t  stride_dw;
    bool     dest_565 = false;  /* G2D_CFG0.FORMAT: false=G2D_8888(7), true=G2D_0565(6) */
    int32_t  clip_l, clip_t, clip_r, clip_b;  /* inclusive px, scissors pre-intersected */
    uint32_t argb;       /* G2D_COLOR, PREMULTIPLIED ARGB8888 (paint setup premultiplies
                            via libOpenVG sub_41C69F40: ch = ch*A/255) */
    bool     even_odd;   /* VGV1_CFG1.WINDRULE: 1=even-odd, 0=nonzero */
    bool     blend;      /* G2D_BLENDERCFG.ENABLE (single-pass only; multi-pass gated) */
    bool     oo_alpha;   /* G2D_BLENDERCFG.OOALPHA: un-premultiply the blend result */
    bool     premult_dst; /* G2D_ALPHABLEND.PREMULTIPLYDST: premultiply the DEST operand
                             (paired with OOALPHA by sub_41C60610 for straight-alpha
                             surfaces, fmt==12427) */
    uint32_t prog_a;     /* G2D_BLEND_A0 alpha-pipe micro-op */
    uint32_t prog_c;     /* G2D_BLEND_C0 color-pipe micro-op */
    /* When set, the per-pixel SOURCE is the GRADW texel sample at (x,y) instead
       of the solid argb (VG-fill gradient paint); null = solid/copy fill. */
    const Gpu2dGradwPaint* paint = nullptr;
};

/* One direct-2D SCOORD1 source->dest copy, decoded by the command engine from the
   g12 register file (BASE0/CFG0 dest + BASE1/CFG1 src + G2D_XY/SXY/WIDTHHEIGHT +
   G2D_SCISSORX/Y). Both surfaces are G2D_8888 linear with all CFG swap fields 0
   (emitter sub_41C6C448 writes CFG=STRIDE|0x7000), so the copy is byte-identical. */
struct Gpu2dCopySpec {
    uint32_t dst_pa;         /* G2D_BASE0 (tile-corner physical; gpuaddr==physical) */
    int32_t  dst_stride_dw;
    uint32_t src_pa;         /* G2D_BASE1 */
    int32_t  src_stride_dw;
    int32_t  clip_l, clip_t, clip_r, clip_b;  /* inclusive dest G2D scissor */
    int32_t  dst_x, dst_y;   /* G2D_XY dest origin (signed 12-bit) */
    int32_t  src_x, src_y;   /* G2D_SXY source origin (unsigned 11-bit) */
    int32_t  w, h;           /* G2D_WIDTHHEIGHT (signed 12-bit) */
};

/* The g12 VGV2 path engine: accumulates MOVETO/LINETO subpaths (curves arrive
   pre-flattened to LineTos) and fills at FLUSH - scanline for integral rectilinear,
   box-filter for fractional rectilinear, 16-subsample contour coverage for diagonals. */
class Imx51Gpu2dRasterizer : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    void MoveTo(float x, float y, bool closed);
    void LineTo(float x, float y);
    bool HasGeometry() const { return !pts_.empty(); }
    void Flush(const Gpu2dFillTarget& t);  /* fill + clear the accumulated path */
    /* Direct-2D engine rect fill (G2D_XY/WIDTHHEIGHT/COLOR, blend-disabled). */
    void FillRect(const Gpu2dFillTarget& t, int32_t x0, int32_t y0, int32_t w, int32_t h);

    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);

    /* Pixel/blend/coverage back-end shared with the stroker (Imx51Gpu2dStroker),
       which resolves this service and hands it the stroke outline - a service
       collaborator, never a second copy (duplicating the blend ALU is banned). */
    [[noreturn]] void HaltFill(const char* why, float a, float b) const;
    void     ValidateBlendProg(uint32_t prog) const;
    static bool BlendProgRefsDest(uint32_t prog);  /* prog reads DEST -> per-pixel */
    uint32_t BlendPixel(const Gpu2dFillTarget& t, uint32_t src, uint32_t dst, float cov) const;
    /* Coverage-fill closed contours (arbitrary edges) under t.even_odd/nonzero
       winding at the g12's VGSPAN 1/16 vertical resolution + exact horizontal
       overlap - the stroke outline and flattened-curve fills. */
    void FillContours(const Gpu2dFillTarget& t,
                      const std::vector<std::vector<float>>& contours,
                      uint32_t const_px, bool per_pixel);
    /* The accumulated centerline the stroker dilates, then clears. */
    const std::vector<float>&    PathPoints() const { return pts_; }
    const std::vector<uint32_t>& PathStarts() const { return starts_; }
    const std::vector<uint8_t>&  PathClosed() const { return closed_; }
    void ClearPath() { pts_.clear(); starts_.clear(); closed_.clear(); }

private:
    [[noreturn]] void HaltBlend(const char* why, uint32_t prog) const;
    /* Byte address of dest pixel (x,y) per t.dest_565 (row stride = stride_dw
       4-byte words); FATAL if unbacked. */
    uint8_t* DestHost(const Gpu2dFillTarget& t, int32_t x, int32_t y);
    uint32_t LoadDest(const Gpu2dFillTarget& t, int32_t x, int32_t y);   /* dest as ARGB8888 */
    void     StoreDest(const Gpu2dFillTarget& t, int32_t x, int32_t y, uint32_t argb);
    /* src = t.paint ? samp->Sample at (x,y) : t.argb (samp resolved once per fill). */
    uint32_t PaintSrc(const Gpu2dFillTarget& t, const Imx51Gpu2dGradwSampler* samp,
                      int32_t x, int32_t y) const;
    void FillRow(const Gpu2dFillTarget& t, int32_t y, int32_t x0, int32_t x1,
                 uint32_t const_px, bool per_pixel, const Imx51Gpu2dGradwSampler* samp);
    /* Exact box-filter coverage fill for fractional RECTILINEAR paths; partial
       pixels are modeled only under the blender (coverage scales the paint). */
    void FlushCoverage(const Gpu2dFillTarget& t, uint32_t const_px, bool per_pixel,
                       const Imx51Gpu2dGradwSampler* samp);

    /* Accumulated subpaths: flat (x,y) pairs; starts_[i] = first point index of
       subpath i. Fill treats every subpath as closed (openvg_spec.pdf printed
       p.100 "Implicit Closure of Filled Subpaths"); closed_[i] is the authored
       closure (MOVETOCLOSED) that Stroke honors (open ends get caps). */
    std::vector<float>    pts_;
    std::vector<uint32_t> starts_;
    std::vector<uint8_t>  closed_;
};
