#define NOMINMAX
#include "imx51_gpu2d_rasterizer.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/state_stream.h"
#include "imx51_gpu2d_blend.h"
#include "imx51_gpu2d_gradw_sampler.h"
#include "imx51_pixel_pack.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

REGISTER_SERVICE(Imx51Gpu2dRasterizer);

bool Imx51Gpu2dRasterizer::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::iMX51;
}

void Imx51Gpu2dRasterizer::HaltFill(const char* why, float a, float b) const {
    LOG(Caution, "[GPU2D-RAST] %s (%.4f, %.4f) - not modeled\n", why, a, b);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void Imx51Gpu2dRasterizer::HaltBlend(const char* why, uint32_t prog) const {
    LOG(Caution, "[GPU2D-RAST] %s prog=0x%08X - not modeled\n", why, prog);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void Imx51Gpu2dRasterizer::MoveTo(float x, float y, bool closed) {
    starts_.push_back(static_cast<uint32_t>(pts_.size() / 2u));
    closed_.push_back(closed ? 1u : 0u);
    pts_.push_back(x);
    pts_.push_back(y);
}

void Imx51Gpu2dRasterizer::LineTo(float x, float y) {
    if (starts_.empty()) HaltFill("LINETO before any MOVETO", x, y);
    pts_.push_back(x);
    pts_.push_back(y);
}

using namespace imx51_g2d_blend;

bool Imx51Gpu2dRasterizer::BlendProgRefsDest(uint32_t prog) {
    for (uint32_t i = 0; i < 4u; ++i)
        if (Src(prog, i) == kSrcDest) return true;
    return false;
}

/* Per-path gate on a single blend micro-op: only ADD over the ZERO/SOURCE/DEST
   selectors with the single-pass TEMP0 output is modeled; every other decoded
   field value halts. */
void Imx51Gpu2dRasterizer::ValidateBlendProg(uint32_t prog) const {
    if (Operation(prog) != 0u)  /* G2D_BLENDOP_ADD (vgenums_z160.h:181-186) */
        HaltBlend("blend OPERATION SUB/MIN/MAX", prog);
    if (Dst(prog, 0) != 1u || Dst(prog, 1) != 0u || Dst(prog, 2) != 0u)
        HaltBlend("blend multi-TEMP routing", prog);
    for (uint32_t i = 0; i < 4u; ++i) {
        if (Const(prog, i))
            HaltBlend("blend CONST operand", prog);
        if (Src(prog, i) > kSrcDest)  /* IMAGE/TEMP0-2 */
            HaltBlend("blend IMAGE/TEMP operand", prog);
    }
}

/* out = (opA*opB) + (opC*opD) per channel; operand = SRC selector value with
   optional alpha-replicate (AR) and inversion (INV = 1-x). Form verified against
   the shipped encoder programs: g2d_BlendSrc_over (sub_41C92FAC) assembles
   C0 = SOURCE*1 + DEST*(1-SOURCE.a) = premultiplied source-over. */
uint32_t Imx51Gpu2dRasterizer::BlendPixel(const Gpu2dFillTarget& t, uint32_t src,
                                          uint32_t dst, float cov) const {
    /* SOURCE = "Paint with coverage alpha applied" (vgenums_z160.h:197): the
       premultiplied paint scaled by the pixel's box-filter path coverage
       before the ALU (the HW edge resolution is VGSPAN.COVERAGE[4] 1/16
       steps; exact area here). */
    if (cov < 1.0f) {
        auto cv = [cov](uint32_t ch) {
            return static_cast<uint32_t>(static_cast<float>(ch) * cov + 0.5f);
        };
        src = (cv(src >> 24) << 24) | (cv((src >> 16) & 0xFFu) << 16)
            | (cv((src >> 8) & 0xFFu) << 8) | cv(src & 0xFFu);
    }
    if (t.premult_dst)  /* straight-alpha dest: premultiply the DEST operand */
        dst = PremultArgb(dst);
    auto chan = [&](uint32_t prog, uint32_t shift) -> uint32_t {
        auto operand = [&](uint32_t i) -> uint32_t {
            const uint32_t sh = Ar(prog, i) ? 24u : shift;
            uint32_t v = 0;
            switch (Src(prog, i)) {
                case kSrcZero:   v = 0; break;
                case kSrcSource: v = (src >> sh) & 0xFFu; break;
                default:         v = (dst >> sh) & 0xFFu; break;  /* DEST (validated) */
            }
            return Inv(prog, i) ? 255u - v : v;
        };
        const uint32_t sum = Mul(operand(0), operand(1)) + Mul(operand(2), operand(3));
        return std::min(sum, 255u);
    };
    const uint32_t a = chan(t.prog_a, 24u);
    uint32_t r = chan(t.prog_c, 16u), g = chan(t.prog_c, 8u), b = chan(t.prog_c, 0u);
    if (t.oo_alpha && a != 255u) {  /* one-over-alpha: un-premultiply the result */
        if (a == 0u) {
            if (r | g | b)
                HaltBlend("OOALPHA divide on zero-alpha nonzero color", t.prog_c);
        } else {
            r = UnpremultChannel(r, a);
            g = UnpremultChannel(g, a);
            b = UnpremultChannel(b, a);
        }
    }
    return (a << 24) | (r << 16) | (g << 8) | b;
}

/* gpuaddr==physical (GPU MMU disabled); row byte stride = stride_dw 4-byte words,
   pixel size 2B (G2D_0565) or 4B (G2D_8888). An unbacked dest pixel halts. */
uint8_t* Imx51Gpu2dRasterizer::DestHost(const Gpu2dFillTarget& t, int32_t x, int32_t y) {
    const uint32_t pa = t.dest_pa + static_cast<uint32_t>(y * t.stride_dw * 4)
                      + static_cast<uint32_t>(x * (t.dest_565 ? 2 : 4));
    uint8_t* hp = emu_.Get<EmulatedMemory>().TryTranslateWrite(pa);
    if (!hp) {
        LOG(Caution, "[GPU2D-RAST] dest pixel unbacked pa=0x%08X (x=%d y=%d)\n", pa, x, y);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    return hp;
}

uint32_t Imx51Gpu2dRasterizer::LoadDest(const Gpu2dFillTarget& t, int32_t x, int32_t y) {
    uint8_t* hp = DestHost(t, x, y);
    if (t.dest_565) {
        /* A blend/coverage read-modify-write into a 565 dest is a distinct
           sub-path not yet exercised; born-FATAL until a 565 dest-reading op
           fires (then modeled with that op's grounding). */
        LOG(Caution, "[GPU2D-RAST] blend read of G2D_0565 dest not modeled (x=%d y=%d)\n", x, y);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    return *reinterpret_cast<const uint32_t*>(hp);
}

void Imx51Gpu2dRasterizer::StoreDest(const Gpu2dFillTarget& t, int32_t x, int32_t y,
                                     uint32_t argb) {
    uint8_t* hp = DestHost(t, x, y);
    if (t.dest_565) *reinterpret_cast<uint16_t*>(hp) = imx51_pixel::PackArgb565(argb);
    else            *reinterpret_cast<uint32_t*>(hp) = argb;
}

uint32_t Imx51Gpu2dRasterizer::PaintSrc(const Gpu2dFillTarget& t,
                                        const Imx51Gpu2dGradwSampler* samp,
                                        int32_t x, int32_t y) const {
    return (t.paint && samp) ? samp->Sample(*t.paint, x, y) : t.argb;
}

/* Fill one inclusive scanline span [x0,x1] at row y, clipped to the target
   rect: const_px when the blend result is pixel-independent, else per-pixel
   dest read-modify-write. */
void Imx51Gpu2dRasterizer::FillRow(const Gpu2dFillTarget& t, int32_t y, int32_t x0, int32_t x1,
                                   uint32_t const_px, bool per_pixel,
                                   const Imx51Gpu2dGradwSampler* samp) {
    if (y < t.clip_t || y > t.clip_b) return;
    x0 = std::max(x0, t.clip_l);
    x1 = std::min(x1, t.clip_r);
    if (x0 > x1) return;
    for (int32_t x = x0; x <= x1; ++x) {
        if (per_pixel)
            StoreDest(t, x, y, BlendPixel(t, PaintSrc(t, samp, x, y), LoadDest(t, x, y), 1.0f));
        else
            StoreDest(t, x, y, const_px);
    }
}

/* Fill rules per openvg_spec.pdf printed p.98 (nonzero: crossing sum != 0;
   even-odd: sum odd); subpaths implicitly closed per printed p.100. */
void Imx51Gpu2dRasterizer::Flush(const Gpu2dFillTarget& t) {
    if (pts_.empty()) { starts_.clear(); closed_.clear(); return; }

    const uint32_t nsub = static_cast<uint32_t>(starts_.size());
    const uint32_t npts = static_cast<uint32_t>(pts_.size() / 2u);

    /* Integral axis-aligned geometry takes the binary scanline (byte-identical
       to the g12 coverage); fractional axis-aligned takes the box-filter path; a
       diagonal edge (a flattened curve, EmitQuad) takes the general 16-subsample
       contour coverage. */
    bool has_diagonal = false;
    for (uint32_t s = 0; s < nsub && !has_diagonal; ++s) {
        const uint32_t first = starts_[s];
        const uint32_t last  = (s + 1u < nsub) ? starts_[s + 1u] : npts;
        for (uint32_t e = first; e < last; ++e) {
            const uint32_t n = e + 1u == last ? first : e + 1u;
            if (pts_[e * 2u] != pts_[n * 2u] && pts_[e * 2u + 1u] != pts_[n * 2u + 1u]) {
                has_diagonal = true;
                break;
            }
        }
    }

    /* Blend programs whose operands never read DEST produce one constant pixel
       (full coverage): fold them once. A GRADW paint varies SOURCE per pixel. */
    const Imx51Gpu2dGradwSampler* samp =
        t.paint ? &emu_.Get<Imx51Gpu2dGradwSampler>() : nullptr;
    uint32_t const_px  = t.argb;
    bool     per_pixel = t.paint != nullptr;
    if (t.blend) {
        ValidateBlendProg(t.prog_a);
        ValidateBlendProg(t.prog_c);
        per_pixel = per_pixel || BlendProgRefsDest(t.prog_a) || BlendProgRefsDest(t.prog_c);
        if (!per_pixel) const_px = BlendPixel(t, t.argb, 0u, 1.0f);
    }

    if (has_diagonal) {  /* general-edge path: one contour per subpath, implicitly closed */
        std::vector<std::vector<float>> contours;
        contours.reserve(nsub);
        for (uint32_t s = 0; s < nsub; ++s) {
            const uint32_t first = starts_[s];
            const uint32_t last  = (s + 1u < nsub) ? starts_[s + 1u] : npts;
            contours.emplace_back(pts_.begin() + first * 2u, pts_.begin() + last * 2u);
        }
        FillContours(t, contours, const_px, per_pixel);
        pts_.clear();
        starts_.clear();
        closed_.clear();
        return;
    }

    bool integral = true;
    for (uint32_t i = 0; i < npts && integral; ++i)
        integral = std::fabs(pts_[i * 2u] - std::round(pts_[i * 2u])) <= 1.0f / 64.0f &&
                   std::fabs(pts_[i * 2u + 1u] - std::round(pts_[i * 2u + 1u])) <= 1.0f / 64.0f;
    if (integral)
        for (uint32_t i = 0; i < npts * 2u; ++i) pts_[i] = std::round(pts_[i]);

    /* Path device-space vertical extent, clipped to the target rect. */
    float miny = pts_[1], maxy = pts_[1];
    for (uint32_t i = 0; i < npts; ++i) {
        miny = std::min(miny, pts_[i * 2u + 1u]);
        maxy = std::max(maxy, pts_[i * 2u + 1u]);
    }
    int32_t y_lo = std::max(t.clip_t, static_cast<int32_t>(std::floor(miny)));
    int32_t y_hi = std::min(t.clip_b, static_cast<int32_t>(std::ceil(maxy)) - 1);

    if (!integral) {
        FlushCoverage(t, const_px, per_pixel, samp);
        pts_.clear();
        starts_.clear();
        closed_.clear();
        return;
    }

    struct Crossing { float x; int dir; };
    std::vector<Crossing> xs;

    for (int32_t y = y_lo; y <= y_hi; ++y) {
        const float sy = static_cast<float>(y) + 0.5f;
        xs.clear();
        for (uint32_t s = 0; s < nsub; ++s) {
            const uint32_t first = starts_[s];
            const uint32_t last  = (s + 1u < nsub) ? starts_[s + 1u] : npts;
            const uint32_t n = last - first;
            if (n < 2u) continue;  /* degenerate subpath: no area */
            for (uint32_t e = 0; e < n; ++e) {
                const uint32_t a = first + e;
                const uint32_t b = first + (e + 1u == n ? 0u : e + 1u);  /* implicit close */
                float ax = pts_[a * 2u], ay = pts_[a * 2u + 1u];
                float bx = pts_[b * 2u], by = pts_[b * 2u + 1u];
                if (ay == by) continue;                       /* horizontal: no crossing */
                int dir = 1;
                if (ay > by) { std::swap(ax, bx); std::swap(ay, by); dir = -1; }
                if (sy < ay || sy >= by) continue;            /* half-open [ay,by) */
                const float x = ax + (bx - ax) * (sy - ay) / (by - ay);
                xs.push_back({x, dir});
            }
        }
        if (xs.empty()) continue;
        std::sort(xs.begin(), xs.end(),
                  [](const Crossing& p, const Crossing& q) { return p.x < q.x; });

        int wind = 0;
        for (size_t i = 0; i + 1u < xs.size(); ++i) {
            wind += xs[i].dir;
            const bool inside = t.even_odd ? ((i + 1u) & 1u) != 0u : (wind != 0);
            if (!inside) continue;
            /* Span [xs[i].x, xs[i+1].x): pixel centers x+0.5 inside the span. */
            const int32_t px0 = static_cast<int32_t>(std::ceil(xs[i].x - 0.5f));
            const int32_t px1 = static_cast<int32_t>(std::ceil(xs[i + 1u].x - 0.5f)) - 1;
            FillRow(t, y, px0, px1, const_px, per_pixel, samp);
        }
    }

    pts_.clear();
    starts_.clear();
    closed_.clear();
}

/* Exact box-filter coverage for a fractional rectilinear path (openvg_spec.pdf
   "Coverage Computation" stage; its Flash-player note mandates single-pixel box
   resolution): the vertical-edge crossing set is constant between vertex-y
   breaks, so pixel coverage = sum of segment-height * x-span overlaps. */
void Imx51Gpu2dRasterizer::FlushCoverage(const Gpu2dFillTarget& t,
                                         uint32_t const_px, bool per_pixel,
                                         const Imx51Gpu2dGradwSampler* samp) {
    const uint32_t nsub = static_cast<uint32_t>(starts_.size());
    const uint32_t npts = static_cast<uint32_t>(pts_.size() / 2u);

    std::vector<float> ybreaks;
    ybreaks.reserve(npts);
    for (uint32_t i = 0; i < npts; ++i) ybreaks.push_back(pts_[i * 2u + 1u]);
    std::sort(ybreaks.begin(), ybreaks.end());
    ybreaks.erase(std::unique(ybreaks.begin(), ybreaks.end()), ybreaks.end());

    const int32_t y_lo = std::max(t.clip_t, static_cast<int32_t>(std::floor(ybreaks.front())));
    const int32_t y_hi = std::min(t.clip_b,
                                  static_cast<int32_t>(std::ceil(ybreaks.back())) - 1);
    const int32_t ncols = t.clip_r - t.clip_l + 1;
    if (ncols <= 0) return;
    std::vector<float> cov(static_cast<size_t>(ncols));

    struct Crossing { float x; int dir; };
    std::vector<Crossing> xs;

    for (int32_t y = y_lo; y <= y_hi; ++y) {
        std::fill(cov.begin(), cov.end(), 0.0f);
        const float ry0 = static_cast<float>(y), ry1 = ry0 + 1.0f;
        for (size_t k = 0; k + 1u < ybreaks.size(); ++k) {
            const float ya = std::max(ybreaks[k], ry0), yb = std::min(ybreaks[k + 1u], ry1);
            if (yb <= ya) continue;
            const float h = yb - ya, my = 0.5f * (ya + yb);
            xs.clear();
            for (uint32_t s = 0; s < nsub; ++s) {
                const uint32_t first = starts_[s];
                const uint32_t n = ((s + 1u < nsub) ? starts_[s + 1u] : npts) - first;
                if (n < 2u) continue;  /* degenerate subpath: no area */
                for (uint32_t e = 0; e < n; ++e) {
                    const uint32_t a = first + e;
                    const uint32_t b = first + (e + 1u == n ? 0u : e + 1u);  /* implicit close */
                    float ay = pts_[a * 2u + 1u], by = pts_[b * 2u + 1u];
                    if (ay == by) continue;               /* horizontal: no crossing */
                    int dir = 1;
                    if (ay > by) { std::swap(ay, by); dir = -1; }
                    if (my < ay || my >= by) continue;    /* half-open [ay,by) */
                    xs.push_back({pts_[a * 2u], dir});    /* axis-aligned: ax == bx */
                }
            }
            if (xs.empty()) continue;
            std::sort(xs.begin(), xs.end(),
                      [](const Crossing& p, const Crossing& q) { return p.x < q.x; });
            int wind = 0;
            for (size_t i = 0; i + 1u < xs.size(); ++i) {
                wind += xs[i].dir;
                const bool inside = t.even_odd ? ((i + 1u) & 1u) != 0u : (wind != 0);
                if (!inside) continue;
                const float x0 = std::max(xs[i].x, static_cast<float>(t.clip_l));
                const float x1 = std::min(xs[i + 1u].x, static_cast<float>(t.clip_r + 1));
                for (int32_t ix = static_cast<int32_t>(std::floor(x0));
                     ix < static_cast<int32_t>(std::ceil(x1)); ++ix) {
                    const float w = std::min(x1, static_cast<float>(ix + 1)) -
                                    std::max(x0, static_cast<float>(ix));
                    if (w > 0.0f) cov[static_cast<size_t>(ix - t.clip_l)] += h * w;
                }
            }
        }
        for (int32_t ix = 0; ix < ncols; ++ix) {
            const float c = std::min(cov[static_cast<size_t>(ix)], 1.0f);
            if (c <= 1.0f / 512.0f) continue;
            const int32_t x = t.clip_l + ix;
            if (c >= 1.0f - 1.0f / 512.0f) {
                if (per_pixel)
                    StoreDest(t, x, y, BlendPixel(t, PaintSrc(t, samp, x, y), LoadDest(t, x, y), 1.0f));
                else
                    StoreDest(t, x, y, const_px);
                continue;
            }
            if (!t.blend)  /* partial coverage composes only through the blender */
                HaltFill("partial coverage with blender disabled", c, static_cast<float>(x));
            StoreDest(t, x, y, BlendPixel(t, PaintSrc(t, samp, x, y), LoadDest(t, x, y), c));
        }
    }
}

/* Coverage of arbitrary-edge contours under t.even_odd/nonzero winding: 16
   sub-scanlines per pixel row (VGSPAN.COVERAGE[4] = the g12's 1/16 vertical
   resolution) with exact horizontal span overlap. Partial pixels compose only
   through the blender. */
void Imx51Gpu2dRasterizer::FillContours(const Gpu2dFillTarget& t,
                                        const std::vector<std::vector<float>>& contours,
                                        uint32_t const_px, bool per_pixel) {
    if (contours.empty()) return;
    float miny = 1e30f, maxy = -1e30f;
    for (const auto& c : contours)
        for (size_t i = 0; i < c.size() / 2u; ++i) {
            miny = std::min(miny, c[i * 2u + 1u]);
            maxy = std::max(maxy, c[i * 2u + 1u]);
        }
    const int32_t y_lo = std::max(t.clip_t, static_cast<int32_t>(std::floor(miny)));
    const int32_t y_hi = std::min(t.clip_b, static_cast<int32_t>(std::ceil(maxy)) - 1);
    const int32_t ncols = t.clip_r - t.clip_l + 1;
    if (ncols <= 0) return;
    std::vector<float> cov(static_cast<size_t>(ncols));
    const Imx51Gpu2dGradwSampler* samp =
        t.paint ? &emu_.Get<Imx51Gpu2dGradwSampler>() : nullptr;

    constexpr int kSub = 16;
    struct Crossing { float x; int dir; };
    std::vector<Crossing> xs;

    for (int32_t y = y_lo; y <= y_hi; ++y) {
        std::fill(cov.begin(), cov.end(), 0.0f);
        for (int k = 0; k < kSub; ++k) {
            const float sy = static_cast<float>(y) + (static_cast<float>(k) + 0.5f) / kSub;
            xs.clear();
            for (const auto& c : contours) {
                const uint32_t m = static_cast<uint32_t>(c.size() / 2u);
                for (uint32_t e = 0; e < m; ++e) {
                    const uint32_t a = e, b = (e + 1u == m) ? 0u : e + 1u;
                    float ax = c[a * 2u], ay = c[a * 2u + 1u];
                    float bx = c[b * 2u], by = c[b * 2u + 1u];
                    if (ay == by) continue;
                    int dir = 1;
                    if (ay > by) { std::swap(ax, bx); std::swap(ay, by); dir = -1; }
                    if (sy < ay || sy >= by) continue;
                    xs.push_back({ax + (bx - ax) * (sy - ay) / (by - ay), dir});
                }
            }
            if (xs.empty()) continue;
            std::sort(xs.begin(), xs.end(),
                      [](const Crossing& p, const Crossing& q) { return p.x < q.x; });
            int wind = 0;
            for (size_t i = 0; i + 1u < xs.size(); ++i) {
                wind += xs[i].dir;
                const bool inside = t.even_odd ? ((i + 1u) & 1u) != 0u : (wind != 0);
                if (!inside) continue;
                const float x0 = std::max(xs[i].x, static_cast<float>(t.clip_l));
                const float x1 = std::min(xs[i + 1u].x, static_cast<float>(t.clip_r + 1));
                for (int32_t ix = static_cast<int32_t>(std::floor(x0));
                     ix < static_cast<int32_t>(std::ceil(x1)); ++ix) {
                    const float w = std::min(x1, static_cast<float>(ix + 1)) -
                                    std::max(x0, static_cast<float>(ix));
                    if (w > 0.0f) cov[static_cast<size_t>(ix - t.clip_l)] += w / kSub;
                }
            }
        }
        for (int32_t ix = 0; ix < ncols; ++ix) {
            const float c = std::min(cov[static_cast<size_t>(ix)], 1.0f);
            if (c <= 1.0f / 512.0f) continue;
            const int32_t x = t.clip_l + ix;
            if (c >= 1.0f - 1.0f / 512.0f) {
                if (per_pixel)
                    StoreDest(t, x, y, BlendPixel(t, PaintSrc(t, samp, x, y), LoadDest(t, x, y), 1.0f));
                else
                    StoreDest(t, x, y, const_px);
                continue;
            }
            if (!t.blend)
                HaltFill("stroke partial coverage with blender disabled", c, static_cast<float>(x));
            StoreDest(t, x, y, BlendPixel(t, PaintSrc(t, samp, x, y), LoadDest(t, x, y), c));
        }
    }
}

void Imx51Gpu2dRasterizer::FillRect(const Gpu2dFillTarget& t, int32_t x0, int32_t y0,
                                    int32_t w, int32_t h) {
    if (w <= 0 || h <= 0) return;  /* zero/negative-area rect writes no pixels */
    for (int32_t y = y0; y < y0 + h; ++y)
        FillRow(t, y, x0, x0 + w - 1, t.argb, false, nullptr);
}


void Imx51Gpu2dRasterizer::SaveState(StateWriter& w) const {
    const uint32_t np = static_cast<uint32_t>(pts_.size());
    w.Write(np);
    for (float f : pts_) w.Write(f);
    const uint32_t ns = static_cast<uint32_t>(starts_.size());
    w.Write(ns);
    for (uint32_t s : starts_) w.Write(s);
    for (uint8_t c : closed_) w.Write(c);
}

void Imx51Gpu2dRasterizer::RestoreState(StateReader& r) {
    uint32_t np = 0;
    r.Read(np);
    pts_.resize(np);
    for (uint32_t i = 0; i < np; ++i) r.Read(pts_[i]);
    uint32_t ns = 0;
    r.Read(ns);
    starts_.resize(ns);
    for (uint32_t i = 0; i < ns; ++i) r.Read(starts_[i]);
    closed_.resize(ns);
    for (uint32_t i = 0; i < ns; ++i) r.Read(closed_[i]);
}
