#include "cerf_virt_blitter.h"
#include "cerf_virt_blt_pixelops.h"
#include "cerf_virt_blt_alpha.h"
#include "cerf_virt_blt_aatext.h"
#include "cerf_virt_framebuffer.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"

namespace CerfVirt {

REGISTER_SERVICE(CerfVirtBlitter);

bool CerfVirtBlitter::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void CerfVirtBlitter::OnReady() {
    fb_  = &emu_.Get<CerfVirtFramebuffer>();
    arena_  = &emu_.Get<CerfVirtDmaArena>();
}

namespace {

[[noreturn]] void FatalSurface(const char* what, const CerfBltSurface& s) {
    LOG(Cerf, "[CerfVirtBlitter] %s surface unresolvable: buffer=0x%08X is_fb_pa=%u fmt=%u "
              "stride=%d stage_off=0x%08X stage_len=%u\n",
        what, s.buffer, s.is_fb_pa, s.format, s.stride, s.stage_off, s.stage_len);
    CerfFatalExit();
}

[[noreturn]] void FatalPixel(const char* what, const CerfBltSurface& s,
                             int32_t x, int32_t y) {
    LOG(Cerf, "[CerfVirtBlitter] %s pixel unaddressable at x=%d y=%d: buffer=0x%08X "
              "is_fb_pa=%u fmt=%u stride=%d stage_off=0x%08X stage_len=%u\n",
        what, x, y, s.buffer, s.is_fb_pa, s.format, s.stride, s.stage_off, s.stage_len);
    CerfFatalExit();
}

void FillAxis(std::vector<int32_t>& lut, int32_t dst_len, int32_t src_len) {
    lut.resize((size_t)dst_len);
    if (dst_len == src_len) {
        for (int32_t i = 0; i < dst_len; ++i) lut[(size_t)i] = i;
        return;
    }
    int32_t src_pos = 0;
    if (dst_len > src_len) {
        const int32_t d_minor = 2 * src_len;
        const int32_t d_major = 2 * src_len - 2 * dst_len;
        int32_t accum = 3 * src_len - 2 * dst_len;
        for (int32_t c = 0; c < dst_len; ++c) {
            lut[(size_t)c] = src_pos;
            if (accum < 0) accum += d_minor;
            else { accum += d_major; ++src_pos; }
        }
    } else {
        const int32_t d_minor = 2 * dst_len;
        const int32_t d_major = 2 * dst_len - 2 * src_len;
        int32_t accum = 2 * dst_len - src_len;
        while (accum < 0) { accum += d_minor; ++src_pos; }
        accum += d_major;
        for (int32_t c = 0; c < dst_len; ++c) {
            lut[(size_t)c] = src_pos;
            ++src_pos;
            while (accum < 0) { ++src_pos; accum += d_minor; }
            accum += d_major;
        }
    }
}
}

bool CerfVirtBlitter::Execute(const CerfBltDescriptor& d) {
    if (d.magic != kCerfBltMagic) {
        LOG(Cerf, "[CerfVirtBlitter] corrupt descriptor magic 0x%08X\n", d.magic);
        CerfFatalExit();
    }

    const uint8_t fg_rop3   = (uint8_t)d.rop4;
    const uint8_t bg_rop3   = (uint8_t)(d.rop4 >> 8);
    const bool transparent  = (d.blt_flags & 0x0004u) != 0u;
    const bool stretch      = (d.blt_flags & 0x0008u) != 0u;
    const bool alpha_blend  = (d.blend_function != 0x00FF0000u);

    int32_t width  = d.dst_rect.right  - d.dst_rect.left;
    int32_t height = d.dst_rect.bottom - d.dst_rect.top;
    bool x_pos = d.x_positive != 0u;
    bool y_pos = d.y_positive != 0u;
    if (width  < 0) { width  = -width;  x_pos = !x_pos; }
    if (height < 0) { height = -height; y_pos = !y_pos; }
    if (width == 0 || height == 0) return true;

    const uint32_t d_bits = BltPixelOps::FormatBits(d.dst.format);
    if (d_bits == 0u) {
        LOG(Cerf, "[CerfVirtBlitter] UNIMPLEMENTED dst format %u, rop4=0x%04X "
                  "has_src=%u has_mask=%u has_brush=%u\n",
            d.dst.format, d.rop4, d.has_src, d.has_mask, d.has_brush);
        CerfFatalExit();
    }
    const bool d_indexed = (d_bits <= 8u);
    const bool d_subbyte = (d_bits < 8u);
    uint32_t d_masks[3] = { 0u, 0u, 0u };
    uint32_t d_shift[3] = { 0u, 0u, 0u };
    uint32_t d_bpp = d_bits / 8u;
    if (!d_indexed) {
        if (!ResolveMasks(d.dst, d_masks, &d_bpp)) {
            LOG(Cerf, "[CerfVirtBlitter] UNIMPLEMENTED dst format %u (%u bpp), "
                      "pal_entries=%u rop4=0x%04X has_src=%u has_mask=%u has_brush=%u\n",
                d.dst.format, d_bits, d.dst.pal_entries,
                d.rop4, d.has_src, d.has_mask, d.has_brush);
            CerfFatalExit();
        }
        for (int i = 0; i < 3; ++i) d_shift[i] = 32u - BltPixelOps::HighBitPos(d_masks[i]);
    }
    if (d_indexed && alpha_blend) {
        LOG(Cerf, "[CerfVirtBlitter] UNIMPLEMENTED alpha blend to indexed dst "
                  "format %u (%u bpp), rop4=0x%04X\n", d.dst.format, d_bits, d.rop4);
        CerfFatalExit();
    }
    if (d_indexed && d.convert_active != 0u) {
        LOG(Cerf, "[CerfVirtBlitter] UNIMPLEMENTED channel conversion to indexed dst "
                  "format %u (%u bpp), src format %u\n",
            d.dst.format, d_bits, d.src.format);
        CerfFatalExit();
    }
    Surface dst;
    if (!ResolveSurface(d.dst, d_subbyte ? 1u : d_bpp, &dst)) FatalSurface("dst", d.dst);

    if ((d.rop4 & 0xFFFFu) == 0xAAF0u && d.has_mask != 0u &&
        d.mask.format == kCerfFmt4Bpp) {
        if (d_indexed) {
            LOG(Cerf, "[CerfVirtBlitter] UNIMPLEMENTED AA text to indexed dst "
                      "format %u (%u bpp)\n", d.dst.format, d_bits);
            CerfFatalExit();
        }
        return BlendAAText(d, dst, d_masks, d_bpp);
    }

    Surface src{};
    uint32_t s_masks[3], s_bpp = 0, s_shift[3], s_bits[3];
    uint32_t pal_lut[256];
    const bool has_src = d.has_src != 0u;
    const uint32_t src_bits = has_src ? BltPixelOps::FormatBits(d.src.format) : 0u;
    const bool src_pal = has_src && (src_bits <= 8u);
    if (has_src) {
        if (src_pal) {
            if (src_bits == 0u) {
                LOG(Cerf, "[CerfVirtBlitter] UNIMPLEMENTED src format %u\n", d.src.format);
                CerfFatalExit();
            }
            if (!ResolveSurface(d.src, 1u, &src)) FatalSurface("src", d.src);
            const uint32_t count = 1u << src_bits;
            if (d.has_lookup != 0u) {
                const uint8_t* lp = arena_->At(d.lookup_off,
                                               count * (uint32_t)sizeof(uint32_t));
                if (!lp) {
                    LOG(Cerf, "[CerfVirtBlitter] XLATEOBJ pLookup outside arena "
                              "off=0x%X entries=%u\n", d.lookup_off, count);
                    CerfFatalExit();
                }
                for (uint32_t i = 0; i < count; ++i)
                    pal_lut[i] = reinterpret_cast<const uint32_t*>(lp)[i];
            } else {
                if (!d_indexed) {
                    LOG(Cerf, "[CerfVirtBlitter] UNIMPLEMENTED indexed src format %u (%u bpp) "
                              "with no XLATEOBJ lookup to non-indexed dst format %u (%u bpp)\n",
                        d.src.format, src_bits, d.dst.format, d_bits);
                    CerfFatalExit();
                }
                for (uint32_t i = 0; i < count; ++i) pal_lut[i] = i;
            }
        } else {
            if (!ResolveMasks(d.src, s_masks, &s_bpp)) {
                LOG(Cerf, "[CerfVirtBlitter] UNIMPLEMENTED src format %u (%u bpp) with no "
                          "XLATEOBJ lookup; dst fmt %u rop4=0x%04X\n",
                    d.src.format, src_bits, d.dst.format, d.rop4);
                CerfFatalExit();
            }
            if (!ResolveSurface(d.src, s_bpp, &src)) FatalSurface("src", d.src);
            for (int i = 0; i < 3; ++i) {
                s_shift[i] = 32u - BltPixelOps::HighBitPos(s_masks[i]);
                s_bits[i]  = BltPixelOps::PopCount(s_masks[i]);
            }
        }
    }

    const uint32_t src_pixmask = (src_bits >= 32u) ? 0xFFFFFFFFu
                               : (src_bits ? ((1u << src_bits) - 1u) : 0u);
    const uint32_t src_rgb = (has_src && !src_pal)
        ? (transparent ? (s_masks[0] | s_masks[1] | s_masks[2]) : src_pixmask) : 0u;
    const uint32_t dst_mask = (d_bits >= 32u) ? 0xFFFFFFFFu : ((1u << d_bits) - 1u);

    Surface mask{};
    const bool has_mask = d.has_mask != 0u;
    if (has_mask && !ResolveSurface(d.mask, 1u, &mask)) FatalSurface("mask", d.mask);

    Surface brush{};
    uint32_t b_masks[3], b_bpp = 0;
    const bool has_brush = d.has_brush != 0u;
    const uint32_t b_bits = has_brush ? BltPixelOps::FormatBits(d.brush.format) : 0u;
    const bool b_indexed  = has_brush && (b_bits <= 8u);
    const bool b_subbyte  = has_brush && (b_bits < 8u);
    if (has_brush) {
        if (b_bits == 0u || (b_indexed != d_indexed)) {
            LOG(Cerf, "[CerfVirtBlitter] UNIMPLEMENTED brush format %u (%u bpp); "
                      "dst fmt %u (%u bpp) rop4=0x%04X\n",
                d.brush.format, b_bits, d.dst.format, d_bits, d.rop4);
            CerfFatalExit();
        }
        if (b_indexed) {
            b_bpp = b_bits / 8u;
        } else if (!BltPixelOps::FormatMasks(d.brush.format, b_masks, &b_bpp)) {
            LOG(Cerf, "[CerfVirtBlitter] UNIMPLEMENTED brush format %u (%u bpp); "
                      "dst fmt %u rop4=0x%04X\n",
                d.brush.format, b_bits, d.dst.format, d.rop4);
            CerfFatalExit();
        }
        if (!ResolveSurface(d.brush, b_subbyte ? 1u : b_bpp, &brush))
            FatalSurface("brush", d.brush);
    }

    BltAlphaContext ac{};
    if (alpha_blend) {
        ac.red_mask = d_masks[0]; ac.green_mask = d_masks[1]; ac.blue_mask = d_masks[2];
        ac.alpha_mask = (d_bpp == 4u) ? 0xFF000000u : 0u;

        ac.red_shift   = BltAlpha::ShiftOf(d_masks[0]);
        ac.green_shift = BltAlpha::ShiftOf(d_masks[1]);
        ac.blue_shift  = BltAlpha::ShiftOf(d_masks[2]);
        ac.alpha_shift = BltAlpha::ShiftOf(ac.alpha_mask);
        ac.red_bits   = BltAlpha::BitsOf(d_masks[0]);
        ac.green_bits = BltAlpha::BitsOf(d_masks[1]);
        ac.blue_bits  = BltAlpha::BitsOf(d_masks[2]);
        ac.alpha_bits = BltAlpha::BitsOf(ac.alpha_mask);
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

    const bool complex = (fg_rop3 != bg_rop3) || transparent || alpha_blend
        || use_lut
        || (fg_rop3 != 0xCCu && (fg_rop3 != 0xF0u || has_brush));

    const uint32_t solid = d.solid_color & dst_mask;
    const int32_t l_indent = (has_brush && d.brush_has_ptl) ? (int32_t)d.brush_width  - d.brush_ptl_x : 0;
    const int32_t t_indent = (has_brush && d.brush_has_ptl) ? (int32_t)d.brush_height - d.brush_ptl_y : 0;
    for (int32_t iy = 0; iy < height; ++iy) {
        const int32_t row = y_pos ? iy : (height - 1 - iy);
        if (d.band_row_count != 0u &&
            ((uint32_t)row < d.band_row_first ||
             (uint32_t)row >= d.band_row_first + d.band_row_count)) continue;
        const int32_t src_dy = use_lut ? sy_lut_[(size_t)row] : row;
        const int32_t src_row_y = d.src_rect.top + src_dy;
        const int32_t dst_y = d.dst_rect.top + row;
        if (d.has_clip && (dst_y < d.clip_rect.top || dst_y >= d.clip_rect.bottom)) continue;
        const int32_t mask_y = d.mask_rect.top + row;

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
                if (!sp) FatalPixel("src", d.src, src_col_x, src_row_y);
                const uint32_t idx = (src_bits == 8u)
                    ? *sp
                    : (uint32_t)((*sp >> (8u - src_bits - (bit_x & 7u))) & ((1u << src_bits) - 1u));
                original_src = idx;
                value = pal_lut[idx];
            } else if (has_src) {
                uint32_t run = 0;
                uint8_t* sp = PixelPtr(src, src_col_x, src_row_y, s_bpp, &run);
                if (!sp) FatalPixel("src", d.src, src_col_x, src_row_y);
                value = (run >= s_bpp)
                    ? BltPixelOps::ReadPixel(sp, s_bpp)
                    : ReadStraddlePixel(src, src_col_x, src_row_y, s_bpp);
                original_src = value & src_rgb;
                if (d.to_mono) {
                    value = (value == d.mono_bg) ? 1u : 0u;
                } else if (d.convert_active) {
                    const uint32_t cv = BltPixelOps::ConvertPixel(value, s_masks, s_shift, s_bits,
                                                                  d_masks, d_shift);
                    value = cv;
                }
            }

            if (complex) {
                uint8_t rop3 = fg_rop3;
                if (has_mask) {
                    const uint32_t mx = (uint32_t)(d.mask_rect.left + col);
                    uint32_t mrun = 0;
                    uint8_t* mp = PixelPtr(mask, (int32_t)(mx >> 3), mask_y, 1u, &mrun);
                    if (!mp) FatalPixel("mask", d.mask, (int32_t)mx, mask_y);
                    rop3 = ((*mp >> lcd_pixel::MsbFirstShift(mx, 1u)) & 1u) ? fg_rop3 : bg_rop3;
                }

                uint32_t brush_val = solid;
                if (has_brush) {
                    const int32_t bx = d.brush_width
                        ? (int32_t)((uint32_t)(l_indent + dst_x) % d.brush_width) : 0;
                    const int32_t by = d.brush_height
                        ? (int32_t)((uint32_t)(t_indent + dst_y) % d.brush_height) : 0;
                    if (b_subbyte) {
                        if (!ReadSubBytePixel(brush, bx, by, b_bits, &brush_val))
                            FatalPixel("brush", d.brush, bx, by);
                    } else {
                        uint32_t brun = 0;
                        uint8_t* bp = PixelPtr(brush, bx, by, b_bpp, &brun);
                        if (!bp) FatalPixel("brush", d.brush, bx, by);
                        brush_val = (brun >= b_bpp)
                            ? BltPixelOps::ReadPixel(bp, b_bpp)
                            : ReadStraddlePixel(brush, bx, by, b_bpp);
                    }
                }

                uint8_t* dp = nullptr;
                uint32_t drun = 0;
                bool dst_straddle = false;
                uint32_t dst_val = 0u;
                if (d_subbyte) {
                    if (dst_matters &&
                        !ReadSubBytePixel(dst, dst_x, dst_y, d_bits, &dst_val))
                        FatalPixel("dst", d.dst, dst_x, dst_y);
                } else {
                    dp = PixelPtr(dst, dst_x, dst_y, d_bpp, &drun);
                    if (!dp) FatalPixel("dst", d.dst, dst_x, dst_y);
                    dst_straddle = (drun < d_bpp);
                    if (dst_matters) {
                        dst_val = dst_straddle
                            ? ReadStraddlePixel(dst, dst_x, dst_y, d_bpp)
                            : BltPixelOps::ReadPixel(dp, d_bpp);
                    }
                }

                value = BltPixelOps::ApplyRop3(rop3, value, dst_val, brush_val, (uint8_t)d_bits);

                if (alpha_blend) {
                    value = BltAlpha::Blend(ac, value, dst_val, original_src);
                }

                value &= dst_mask;
                const bool keyed = (rop3 == 0xAAu || (transparent && original_src == d.solid_color));
                if (keyed) {
                    continue;
                }
                if (d_subbyte) {
                    if (!WriteSubBytePixel(dst, dst_x, dst_y, d_bits, value))
                        FatalPixel("dst", d.dst, dst_x, dst_y);
                } else if (dst_straddle) {
                    WriteStraddlePixel(dst, dst_x, dst_y, d_bpp, value);
                } else {
                    BltPixelOps::WritePixel(dp, d_bpp, value);
                }
            } else {
                value &= dst_mask;
                if (d_subbyte) {
                    if (!WriteSubBytePixel(dst, dst_x, dst_y, d_bits, value))
                        FatalPixel("dst", d.dst, dst_x, dst_y);
                } else {
                    uint32_t drun = 0;
                    uint8_t* dp = PixelPtr(dst, dst_x, dst_y, d_bpp, &drun);
                    if (!dp) FatalPixel("dst", d.dst, dst_x, dst_y);
                    if (drun >= d_bpp) BltPixelOps::WritePixel(dp, d_bpp, value);
                    else               WriteStraddlePixel(dst, dst_x, dst_y, d_bpp, value);
                }
            }
        }
    }

    fb_->MarkDirty();
    return true;
}

bool CerfVirtBlitter::BlendAAText(const CerfBltDescriptor& d, Surface& dst,
                                  const uint32_t d_masks[3], uint32_t d_bpp) {
    Surface mask;
    if (!ResolveSurface(d.mask, 1u, &mask)) FatalSurface("AA-text mask", d.mask);
    AATextContext aa;
    aa.Build(d_masks, d.solid_color);
    const uint32_t on_color = d.solid_color & cerf::ByteWidthMask(d_bpp);

    const int32_t width  = d.dst_rect.right  - d.dst_rect.left;
    const int32_t height = d.dst_rect.bottom - d.dst_rect.top;
    for (int32_t iy = 0; iy < height; ++iy) {
        if (d.band_row_count != 0u &&
            ((uint32_t)iy < d.band_row_first ||
             (uint32_t)iy >= d.band_row_first + d.band_row_count)) continue;
        const int32_t dst_y  = d.dst_rect.top  + iy;
        const int32_t mask_y = d.mask_rect.top + iy;
        if (d.has_clip && (dst_y < d.clip_rect.top || dst_y >= d.clip_rect.bottom)) continue;
        for (int32_t ix = 0; ix < width; ++ix) {
            const int32_t dst_x = d.dst_rect.left + ix;
            if (d.has_clip && (dst_x < d.clip_rect.left || dst_x >= d.clip_rect.right)) continue;
            const int32_t mask_x = d.mask_rect.left + ix;

            uint32_t mrun = 0;
            uint8_t* mp = PixelPtr(mask, mask_x >> 1, mask_y, 1u, &mrun);
            if (!mp) FatalPixel("AA-text mask", d.mask, mask_x, mask_y);
            const uint32_t cov = (mask_x & 1) ? (uint32_t)(*mp & 0x0Fu)
                                              : (uint32_t)(*mp >> 4);
            if (cov == 0u) continue;
            uint32_t drun = 0;
            uint8_t* dp = PixelPtr(dst, dst_x, dst_y, d_bpp, &drun);
            if (!dp) FatalPixel("AA-text dst", d.dst, dst_x, dst_y);
            const bool straddle = (drun < d_bpp);
            uint32_t v;
            if (cov >= 15u) {
                v = on_color;
            } else {
                const uint32_t dv = straddle
                    ? ReadStraddlePixel(dst, dst_x, dst_y, d_bpp)
                    : BltPixelOps::ReadPixel(dp, d_bpp);
                v = aa.BlendAA(dv, cov);
            }
            if (straddle) WriteStraddlePixel(dst, dst_x, dst_y, d_bpp, v);
            else          BltPixelOps::WritePixel(dp, d_bpp, v);
        }
    }
    fb_->MarkDirty();
    return true;
}

}
