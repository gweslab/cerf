#include "cerf_virt_blitter.h"
#include "cerf_virt_blt_pixelops.h"
#include "cerf_virt_blt_alpha.h"
#include "cerf_virt_framebuffer.h"
#include "cerf_virt_addr_map.h"

#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"

namespace CerfVirt {

REGISTER_SERVICE(CerfVirtBlitter);

bool CerfVirtBlitter::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void CerfVirtBlitter::OnReady() {
    fb_  = &emu_.Get<CerfVirtFramebuffer>();
    mmu_ = &emu_.Get<ArmMmu>();
}

bool CerfVirtBlitter::ResolveSurface(const CerfBltSurface& s, uint32_t bpp,
                                     Surface* out) {
    out->desc = &s;
    out->bpp  = bpp;
    out->is_va = (s.is_fb_pa == 0u);
    out->host_base = nullptr;
    if (!out->is_va) {
        const uint32_t fb_base = CerfVirt::kFramebufferMemBase;
        const uint32_t fb_size = fb_->RegionBytes();
        if (s.buffer < fb_base) return false;
        const uint32_t off = s.buffer - fb_base;
        if (off >= fb_size) return false;
        out->host_base = fb_->Bytes() + off;
    }
    return true;
}

/* Rotated surface: map logical (x,y) to the physical byte via the 4-angle
   transform (WINCE600 pixeliterator.cpp GetPtr). screen_w/h are physical dims
   minus 1 (0-indexed), matching ScreenWidth()-1 / ScreenHeight()-1 at Init. */
uint8_t* CerfVirtBlitter::RotatedPixelPtr(const Surface& s, int32_t x, int32_t y) {
    const CerfBltSurface& d = *s.desc;
    const int32_t stride = d.stride;
    const int32_t bpp    = (int32_t)s.bpp;
    const int32_t W = (int32_t)d.screen_w - 1;
    const int32_t H = (int32_t)d.screen_h - 1;
    int32_t off;
    switch (d.rotate) {
    case kCerfRotate90:  off = (H - x) * stride + y * bpp;            break;
    case kCerfRotate180: off = (H - y) * stride + (W - x) * bpp;      break;
    case kCerfRotate270: off = x * stride + (W - y) * bpp;            break;
    default:             off = y * stride + x * bpp;                  break;
    }
    if (!s.is_va) return s.host_base + off;
    return mmu_->PeekVaToHost(d.buffer + (uint32_t)off);
}

/* Host pointer to pixel (x,y) plus the contiguous byte run available from there
   (run >= bpp on success). Rotated surfaces resolve one pixel at a time
   (addresses jump); linear FB-PA spans to region end; linear VA spans to page
   end. */
uint8_t* CerfVirtBlitter::PixelPtr(const Surface& s, int32_t x, int32_t y,
                                   uint32_t run_bytes, uint32_t* run) {
    if (s.desc->is_rotate) {
        uint8_t* p = RotatedPixelPtr(s, x, y);
        if (!p) return nullptr;
        *run = s.bpp;
        return p;
    }
    const uint32_t off = (uint32_t)y * (uint32_t)s.desc->stride + (uint32_t)x * s.bpp;
    if (!s.is_va) {
        const uint32_t fb_size = fb_->RegionBytes();
        const uint32_t base_off = (uint32_t)(s.host_base - fb_->Bytes());
        if (base_off + off >= fb_size) return nullptr;
        const uint32_t avail = fb_size - (base_off + off);
        *run = run_bytes < avail ? run_bytes : avail;
        return s.host_base + off;
    }
    const uint32_t va = s.desc->buffer + off;
    uint8_t* p = mmu_->PeekVaToHost(va);
    if (!p) return nullptr;
    const uint32_t page_left = 0x1000u - (va & 0x0FFFu);
    *run = run_bytes < page_left ? run_bytes : page_left;
    return p;
}

/* A 24bpp (3-byte) source pixel — or any multi-byte pixel — can straddle a 4KB
   page whose two halves map to non-adjacent host pages, so a single host read of
   bpp bytes from PixelPtr would cross into the wrong page. Assemble it byte-by-
   byte: the guest VA is contiguous, so each byte translates independently. */
uint32_t CerfVirtBlitter::ReadStraddlePixel(const Surface& s, int32_t x, int32_t y,
                                            uint32_t bpp) {
    uint32_t v = 0;
    if (s.is_va) {
        const uint32_t va = s.desc->buffer
                          + (uint32_t)y * (uint32_t)s.desc->stride + (uint32_t)x * bpp;
        for (uint32_t i = 0; i < bpp; ++i) {
            uint8_t* bp = mmu_->PeekVaToHost(va + i);
            if (bp) v |= (uint32_t)(*bp) << (8u * i);
        }
    } else {
        const uint32_t off = (uint32_t)y * (uint32_t)s.desc->stride + (uint32_t)x * bpp;
        const uint32_t fb_size  = fb_->RegionBytes();
        const uint32_t base_off = (uint32_t)(s.host_base - fb_->Bytes());
        for (uint32_t i = 0; i < bpp; ++i) {
            if (base_off + off + i < fb_size)
                v |= (uint32_t)(s.host_base[off + i]) << (8u * i);
        }
    }
    return v;
}

void CerfVirtBlitter::WriteStraddlePixel(const Surface& s, int32_t x, int32_t y,
                                         uint32_t bpp, uint32_t value) {
    if (s.is_va) {
        const uint32_t va = s.desc->buffer
                          + (uint32_t)y * (uint32_t)s.desc->stride + (uint32_t)x * bpp;
        for (uint32_t i = 0; i < bpp; ++i) {
            uint8_t* bp = mmu_->PeekVaToHost(va + i);
            if (bp) *bp = (uint8_t)(value >> (8u * i));
        }
    } else {
        const uint32_t off = (uint32_t)y * (uint32_t)s.desc->stride + (uint32_t)x * bpp;
        const uint32_t fb_size  = fb_->RegionBytes();
        const uint32_t base_off = (uint32_t)(s.host_base - fb_->Bytes());
        for (uint32_t i = 0; i < bpp; ++i) {
            if (base_off + off + i < fb_size)
                s.host_base[off + i] = (uint8_t)(value >> (8u * i));
        }
    }
}

namespace {
/* Per-dst-index source offset for one axis. MUST replicate swblt.cpp's exact
   accumulator walk (402-530, 759-913), NOT floor(c*src/dst) — they differ
   (2->3 stretch is 0,1,1 not 0,0,1) and a mismatch is +/-1px corruption. */
void FillAxis(std::vector<int32_t>& lut, int32_t dst_len, int32_t src_len) {
    lut.resize((size_t)dst_len);
    if (dst_len == src_len) {
        for (int32_t i = 0; i < dst_len; ++i) lut[(size_t)i] = i;
        return;
    }
    int32_t src_pos = 0;
    if (dst_len > src_len) {                 /* stretch: repeat source pixels */
        const int32_t d_minor = 2 * src_len;
        const int32_t d_major = 2 * src_len - 2 * dst_len;
        int32_t accum = 3 * src_len - 2 * dst_len;
        for (int32_t c = 0; c < dst_len; ++c) {
            lut[(size_t)c] = src_pos;
            if (accum < 0) accum += d_minor;             /* repeat this src pixel */
            else { accum += d_major; ++src_pos; }        /* advance to next */
        }
    } else {                                 /* shrink: skip source pixels */
        const int32_t d_minor = 2 * dst_len;
        const int32_t d_major = 2 * dst_len - 2 * src_len;
        int32_t accum = 2 * dst_len - src_len;
        while (accum < 0) { accum += d_minor; ++src_pos; }   /* pre-skip (469-477) */
        accum += d_major;
        for (int32_t c = 0; c < dst_len; ++c) {
            lut[(size_t)c] = src_pos;
            ++src_pos;                                    /* read's implicit advance */
            while (accum < 0) { ++src_pos; accum += d_minor; }
            accum += d_major;
        }
    }
}

/* Channel masks for an RGB surface. The reference uses each surface's real
   m_pPalette masks (carried as pal_entries/mask), never an assumed set — some
   CE5 16bpp surfaces are BGR565 (R=0x001F,B=0xF800), not RGB565. Fall back to
   the per-format assumption only when the surface reports no real masks. */
bool ResolveMasks(const CerfBltSurface& s, uint32_t m[3], uint32_t* bpp) {
    const uint32_t bits = BltPixelOps::FormatBits(s.format);
    if (bits < 8u) return false;
    *bpp = bits / 8u;
    if (s.pal_entries >= 3u && (s.mask[0] | s.mask[1] | s.mask[2]) != 0u) {
        m[0] = s.mask[0]; m[1] = s.mask[1]; m[2] = s.mask[2];
        return true;
    }
    uint32_t ignore;
    return BltPixelOps::FormatMasks(s.format, m, &ignore);
}

/* Floor division (round toward -inf) with span > 0, matching the gradient
   step sub_17D1518 computes — C truncation would round a negative delta the
   wrong way and shift the ramp by one LSB. */
int64_t GradFloorDiv(int64_t num, int64_t span) {
    int64_t q = num / span;
    if (num % span != 0 && num < 0) --q;
    return q;
}
}  /* namespace */

bool CerfVirtBlitter::Execute(const CerfBltDescriptor& d) {
    if (d.magic != kCerfBltMagic) {
        LOG(Periph, "[CerfVirtBlitter] bad descriptor magic 0x%08X\n", d.magic);
        return false;
    }

    const uint8_t fg_rop3   = (uint8_t)d.rop4;
    const uint8_t bg_rop3   = (uint8_t)(d.rop4 >> 8);
    const bool transparent  = (d.blt_flags & 0x0004u) != 0u; /* BLT_TRANSPARENT */
    const bool stretch      = (d.blt_flags & 0x0008u) != 0u; /* BLT_STRETCH */
    /* Alpha is signaled by a non-null blendFunction, NOT a bltFlag (swblt.cpp:277).
       g_NullBlendFunction = {0,0,0xFF,0} = 0x00FF0000 packed LE (ddi_if.cpp:101). */
    const bool alpha_blend  = (d.blend_function != 0x00FF0000u);

    int32_t width  = d.dst_rect.right  - d.dst_rect.left;
    int32_t height = d.dst_rect.bottom - d.dst_rect.top;
    bool x_pos = d.x_positive != 0u;
    bool y_pos = d.y_positive != 0u;
    if (width  < 0) { width  = -width;  x_pos = !x_pos; }  /* swblt.cpp:382-398 */
    if (height < 0) { height = -height; y_pos = !y_pos; }
    if (width == 0 || height == 0) return true;

    uint32_t d_masks[3], d_bpp = 0, d_shift[3];
    if (!ResolveMasks(d.dst, d_masks, &d_bpp)) {
        LOG(Periph, "[CerfVirtBlitter] unsupported dst format %u\n", d.dst.format);
        return false;
    }
    for (int i = 0; i < 3; ++i) d_shift[i] = 32u - BltPixelOps::HighBitPos(d_masks[i]);
    Surface dst;
    if (!ResolveSurface(d.dst, d_bpp, &dst)) return false;

    Surface src{};
    uint32_t s_masks[3], s_bpp = 0, s_shift[3], s_bits[3];
    uint32_t pal_lut[256];                                   /* palettized src: pLookup read once */
    const bool has_src = d.has_src != 0u;
    const bool src_pal = has_src && (d.lookup_va != 0u);     /* palettized index source */
    const uint32_t src_bits = has_src ? BltPixelOps::FormatBits(d.src.format) : 0u;
    if (has_src) {
        if (src_pal) {
            if (src_bits == 0u || src_bits > 8u) {
                LOG(Periph, "[CerfVirtBlitter] bad palettized src format %u\n", d.src.format);
                return false;
            }
            if (!ResolveSurface(d.src, 1u, &src)) return false;   /* byte addressing */
            /* Read the whole pLookup table once: each 4-aligned ULONG entry is
               page-safe, avoiding a per-pixel MMU walk + page-boundary cross. */
            const uint32_t count = 1u << src_bits;               /* 2/4/16/256 */
            for (uint32_t i = 0; i < count; ++i) {
                uint8_t* lp = mmu_->PeekVaToHost(d.lookup_va + i * 4u);
                if (!lp) return false;
                pal_lut[i] = *reinterpret_cast<uint32_t*>(lp);
            }
        } else {
            if (!ResolveMasks(d.src, s_masks, &s_bpp)) {
                LOG(Periph, "[CerfVirtBlitter] unsupported src format %u\n", d.src.format);
                return false;
            }
            if (!ResolveSurface(d.src, s_bpp, &src)) return false;
            for (int i = 0; i < 3; ++i) {
                s_shift[i] = 32u - BltPixelOps::HighBitPos(s_masks[i]);
                s_bits[i]  = BltPixelOps::PopCount(s_masks[i]);
            }
        }
    }

    /* swblt.cpp:551-571: SrcRGBMask is the RGB-channel union for a transparent
       blt (key compare) but the FULL source pixel mask otherwise, so original_src
       keeps the alpha channel for BLT_ALPHABLEND. */
    const uint32_t src_pixmask = (src_bits >= 32u) ? 0xFFFFFFFFu
                               : (src_bits ? ((1u << src_bits) - 1u) : 0u);
    const uint32_t src_rgb = (has_src && !src_pal)
        ? (transparent ? (s_masks[0] | s_masks[1] | s_masks[2]) : src_pixmask) : 0u;
    const uint32_t dst_mask = (d_bpp >= 4) ? 0xFFFFFFFFu : ((1u << (d_bpp * 8u)) - 1u);

    Surface mask{};
    const bool has_mask = d.has_mask != 0u;
    if (has_mask && !ResolveSurface(d.mask, 1u, &mask)) return false;

    Surface brush{};
    uint32_t b_masks[3], b_bpp = 0;
    const bool has_brush = d.has_brush != 0u;
    if (has_brush) {
        if (!BltPixelOps::FormatMasks(d.brush.format, b_masks, &b_bpp)) return false;
        if (!ResolveSurface(d.brush, b_bpp, &brush)) return false;
    }

    BltAlphaContext ac{};
    if (alpha_blend) {
        ac.red_mask = d_masks[0]; ac.green_mask = d_masks[1]; ac.blue_mask = d_masks[2];
        ac.alpha_mask = (d_bpp == 4u) ? 0xFF000000u : 0u;
        /* Blend reads channels as (px & mask) >> shift to an 8-bit value, so the
           shift is the mask's trailing-zero count, not the 32-HighBitPos left-pack
           shift d_shift carries — that one mis-aligns RGB and collapses opaque
           pixels to 0xFF000000 (black). */
        ac.red_shift   = BltAlpha::ShiftOf(d_masks[0]);
        ac.green_shift = BltAlpha::ShiftOf(d_masks[1]);
        ac.blue_shift  = BltAlpha::ShiftOf(d_masks[2]);
        ac.alpha_shift = BltAlpha::ShiftOf(ac.alpha_mask);
        ac.src_alpha_mask = 0xFF000000u; ac.src_alpha_shift = 24u;
        ac.const_alpha = (uint8_t)(d.blend_function >> 16);
        ac.alpha_format = (uint8_t)(d.blend_function >> 24);
        ac.blend_flags = (d.blend_function >> 8) & 0xFFu;
    }

    const bool dst_matters = alpha_blend || BltPixelOps::DestMatters(d.rop4);

    const int32_t src_w = d.src_rect.right - d.src_rect.left;
    const int32_t src_h = d.src_rect.bottom - d.src_rect.top;
    const bool use_lut = stretch && (src_w != width || src_h != height);
    if (use_lut) { FillAxis(sx_lut_, width, src_w); FillAxis(sy_lut_, height, src_h); }

    /* complexBlt (swblt.cpp:656-660): brush/mask/transparent/alpha/stretch or an
       unusual rop. Otherwise the per-pixel loop just writes the (converted) src
       or the solid fill. */
    const bool complex = (fg_rop3 != bg_rop3) || transparent || alpha_blend
        || use_lut
        || (fg_rop3 != 0xCCu && (fg_rop3 != 0xF0u || has_brush));

    const uint32_t solid = d.solid_color & dst_mask;
    const int32_t l_indent = (has_brush && d.brush_has_ptl) ? (int32_t)d.brush_width  - d.brush_ptl_x : 0;
    const int32_t t_indent = (has_brush && d.brush_has_ptl) ? (int32_t)d.brush_height - d.brush_ptl_y : 0;
    for (int32_t iy = 0; iy < height; ++iy) {
        /* iy drives draw ORDER (y_pos = overlap-safe direction); row is the
           MAPPING offset. dst_y and src_row_y both derive from row, so
           !y_pos reverses order without mirroring (swblt.cpp:605-614 + the
           src iterator flip move together). */
        const int32_t row = y_pos ? iy : (height - 1 - iy);
        const int32_t src_dy = use_lut ? sy_lut_[(size_t)row] : row;
        const int32_t src_row_y = d.src_rect.top + src_dy;
        const int32_t dst_y = d.dst_rect.top + row;
        if (d.has_clip && (dst_y < d.clip_rect.top || dst_y >= d.clip_rect.bottom)) continue;
        const int32_t mask_y = d.mask_rect.top + src_dy;

        for (int32_t ix = 0; ix < width; ++ix) {
            const int32_t col = x_pos ? ix : (width - 1 - ix);
            const int32_t src_dx = use_lut ? sx_lut_[(size_t)col] : col;
            const int32_t src_col_x = d.src_rect.left + src_dx;
            const int32_t dst_x = d.dst_rect.left + col;
            if (d.has_clip && (dst_x < d.clip_rect.left || dst_x >= d.clip_rect.right)) continue;

            uint32_t value = solid;
            uint32_t original_src = 0u;
            if (has_src && src_pal) {
                const uint32_t bit_x = (uint32_t)src_col_x * src_bits;
                uint32_t run = 0;
                uint8_t* sp = PixelPtr(src, (int32_t)(bit_x >> 3), src_row_y, 1u, &run);
                if (!sp) return false;
                const uint32_t idx = (src_bits == 8u)
                    ? *sp
                    : (uint32_t)((*sp >> (8u - src_bits - (bit_x & 7u))) & ((1u << src_bits) - 1u));
                original_src = idx;                       /* key compared as palette index */
                value = pal_lut[idx];
            } else if (has_src) {
                uint32_t run = 0;
                uint8_t* sp = PixelPtr(src, src_col_x, src_row_y, s_bpp, &run);
                if (!sp) return false;
                value = (run >= s_bpp)
                    ? BltPixelOps::ReadPixel(sp, s_bpp)
                    : ReadStraddlePixel(src, src_col_x, src_row_y, s_bpp);
                original_src = value & src_rgb;
                if (d.convert_active) {
                    const uint32_t cv = BltPixelOps::ConvertPixel(value, s_masks, s_shift, s_bits,
                                                                  d_masks, d_shift);
                    value = cv;
                }
            }

            if (complex) {
                uint8_t rop3 = fg_rop3;
                if (has_mask) {
                    const uint32_t mx = (uint32_t)(d.mask_rect.left + src_dx);
                    uint32_t mrun = 0;
                    uint8_t* mp = PixelPtr(mask, (int32_t)(mx >> 3), mask_y, 1u, &mrun);
                    if (!mp) return false;
                    rop3 = (*mp & (0x80u >> (mx & 7u))) ? fg_rop3 : bg_rop3;
                }

                uint32_t brush_val = solid;
                if (has_brush) {
                    const int32_t bx = d.brush_width
                        ? (int32_t)((uint32_t)(l_indent + dst_x) % d.brush_width) : 0;
                    const int32_t by = d.brush_height
                        ? (int32_t)((uint32_t)(t_indent + dst_y) % d.brush_height) : 0;
                    uint32_t brun = 0;
                    uint8_t* bp = PixelPtr(brush, bx, by, b_bpp, &brun);
                    if (!bp) return false;
                    brush_val = (brun >= b_bpp)
                        ? BltPixelOps::ReadPixel(bp, b_bpp)
                        : ReadStraddlePixel(brush, bx, by, b_bpp);
                }

                uint32_t drun = 0;
                uint8_t* dp = PixelPtr(dst, dst_x, dst_y, d_bpp, &drun);
                if (!dp) return false;
                const bool dst_straddle = (drun < d_bpp);
                const uint32_t dst_val = !dst_matters ? 0u
                    : (dst_straddle ? ReadStraddlePixel(dst, dst_x, dst_y, d_bpp)
                                    : BltPixelOps::ReadPixel(dp, d_bpp));

                value = BltPixelOps::ApplyRop3(rop3, value, dst_val, brush_val, (uint8_t)(d_bpp * 8u));

                /* value is already in dst format here (lookup+convert ran upstream),
                   so Blend uses the dst-format masks in ac directly. */
                if (alpha_blend) {
                    value = BltAlpha::Blend(ac, value, dst_val, original_src);
                }

                value &= dst_mask;
                const bool keyed = (rop3 == 0xAAu || (transparent && original_src == d.solid_color));
                if (keyed) {
                    continue;  /* NOP / transparent key: leave dst (swblt.cpp:1238) */
                }
                if (dst_straddle) WriteStraddlePixel(dst, dst_x, dst_y, d_bpp, value);
                else              BltPixelOps::WritePixel(dp, d_bpp, value);
            } else {
                value &= dst_mask;
                uint32_t drun = 0;
                uint8_t* dp = PixelPtr(dst, dst_x, dst_y, d_bpp, &drun);
                if (!dp) return false;
                if (drun >= d_bpp) BltPixelOps::WritePixel(dp, d_bpp, value);
                else               WriteStraddlePixel(dst, dst_x, dst_y, d_bpp, value);
            }
        }
    }

    fb_->MarkDirty();
    return true;
}

bool CerfVirtBlitter::ExecuteGradient(const CerfGradDescriptor& g) {
    if (g.magic != kCerfGradMagic) {
        LOG(Periph, "[CerfVirtBlitter] bad gradient magic 0x%08X\n", g.magic);
        return false;
    }
    const int32_t span = g.end_coord - g.start_coord;
    if (span <= 0) return true;

    uint32_t d_masks[3], d_bpp = 0, d_shift[3];
    if (!ResolveMasks(g.dst, d_masks, &d_bpp)) {
        LOG(Periph, "[CerfVirtBlitter] gradient unsupported dst format %u\n", g.dst.format);
        return false;
    }
    for (int i = 0; i < 3; ++i) d_shift[i] = 32u - BltPixelOps::HighBitPos(d_masks[i]);
    /* 32bpp writes the alpha channel only when the surface carries an ARGB
       mask set (sub_17D3434 case 6: alpha packed iff pal entries == 4). */
    const uint32_t a_mask  = (g.dst.pal_entries == 4u) ? g.dst.mask[3] : 0u;
    const uint32_t a_shift = a_mask ? 32u - BltPixelOps::HighBitPos(a_mask) : 0u;

    Surface dst;
    if (!ResolveSurface(g.dst, d_bpp, &dst)) return false;

    /* Per-channel base = COLOR16<<8 in the high dword; step = fixed-point
       per-unit delta. Output 8-bit channel = high byte of the <<8 value
       (bits 48..55 of the 64-bit accumulator). */
    int64_t base[4], step[4];
    for (int c = 0; c < 4; ++c) {
        base[c] = (int64_t)((uint32_t)g.start_color[c] << 8) << 32;
        const int64_t delta = ((int64_t)g.end_color[c] << 8) - ((int64_t)g.start_color[c] << 8);
        step[c] = GradFloorDiv(delta << 32, span);
    }

    const CerfBltRect& r = g.fill_rect;
    const bool horiz = (g.axis == kCerfGradAxisH);
    const int32_t n = horiz ? (r.right - r.left) : (r.bottom - r.top);
    if (n <= 0) return true;
    const int32_t origin = horiz ? r.left : r.top;
    std::vector<uint32_t> line((size_t)n);
    for (int32_t i = 0; i < n; ++i) {
        int32_t t = (origin + i) - g.start_coord;
        if (t < 0) t = 0; else if (t > span) t = span;
        uint32_t px = 0u;
        for (int c = 0; c < 3; ++c) {
            const uint8_t c8 = (uint8_t)((base[c] + step[c] * (int64_t)t) >> 48);
            px |= (((uint32_t)c8 << 24) >> d_shift[c]) & d_masks[c];
        }
        if (a_mask) {
            const uint8_t a8 = (uint8_t)((base[3] + step[3] * (int64_t)t) >> 48);
            px |= (((uint32_t)a8 << 24) >> a_shift) & a_mask;
        }
        line[(size_t)i] = px;
    }

    for (int32_t y = r.top; y < r.bottom; ++y) {
        const uint32_t row_px = horiz ? 0u : line[(size_t)(y - r.top)];
        for (int32_t x = r.left; x < r.right; ++x) {
            const uint32_t px = horiz ? line[(size_t)(x - r.left)] : row_px;
            uint32_t run = 0;
            uint8_t* dp = PixelPtr(dst, x, y, d_bpp, &run);
            if (!dp) continue;
            if (run >= d_bpp) BltPixelOps::WritePixel(dp, d_bpp, px);
            else              WriteStraddlePixel(dst, x, y, d_bpp, px);
        }
    }
    fb_->MarkDirty();
    return true;
}

}  /* namespace CerfVirt */
