#pragma once

#include "cerf_virt_blt_descriptor.h"
#include "cerf_virt_blt_pixelops.h"
#include "cerf_virt_framebuffer.h"
#include "cerf_virt_dma_arena.h"
#include "../../core/log.h"
#include "../../lcd/lcd_pixel_expand.h"

#include <cstdint>

namespace CerfVirt {

class BltSurfaceAccess {
public:
    struct Surface {
        const CerfBltSurface* desc;
        uint32_t bpp;
        uint8_t* host_base;
        uint8_t* host_lo;
        uint8_t* host_hi;
    };

protected:
    bool ResolveSurface(const CerfBltSurface& s, uint32_t bpp, Surface* out);
    uint8_t* PixelPtr(const Surface& s, int32_t x, int32_t y, uint32_t run_bytes,
                      uint32_t* run);
    uint8_t* RotatedPixelPtr(const Surface& s, int32_t x, int32_t y);
    uint32_t ReadStraddlePixel(const Surface& s, int32_t x, int32_t y, uint32_t bpp);
    void     WriteStraddlePixel(const Surface& s, int32_t x, int32_t y,
                                uint32_t bpp, uint32_t value);
    bool ReadSubBytePixel(const Surface& s, int32_t x, int32_t y, uint32_t bits,
                          uint32_t* out);
    bool WriteSubBytePixel(const Surface& s, int32_t x, int32_t y, uint32_t bits,
                           uint32_t value);

    [[noreturn]] void FatalStraddle(const Surface& s, int32_t x, int32_t y,
                                    uint32_t off) {
        LOG(Cerf, "[BltSurfaceAccess] pixel byte unaddressable at x=%d y=%d "
                  "off=%u: buffer=0x%08X is_fb_pa=%u fmt=%u stride=%d "
                  "stage_off=0x%08X stage_len=%u\n",
            x, y, off, s.desc->buffer, s.desc->is_fb_pa, s.desc->format,
            s.desc->stride, s.desc->stage_off, s.desc->stage_len);
        CerfFatalExit();
    }

    CerfVirtFramebuffer* fb_ = nullptr;
    CerfVirtDmaArena*    arena_ = nullptr;
};

inline bool ResolveMasks(const CerfBltSurface& s, uint32_t m[3], uint32_t* bpp) {
    const uint32_t bits = BltPixelOps::FormatBits(s.format);
    if (bits < 8u) return false;
    *bpp = bits / 8u;
    m[0] = m[1] = m[2] = 0u;
    if (s.pal_entries >= 3u && (s.mask[0] | s.mask[1] | s.mask[2]) != 0u) {
        m[0] = s.mask[0]; m[1] = s.mask[1]; m[2] = s.mask[2];
        return true;
    }
    uint32_t ignore;
    return BltPixelOps::FormatMasks(s.format, m, &ignore);
}

inline bool BltSurfaceAccess::ResolveSurface(const CerfBltSurface& s, uint32_t bpp,
                                             Surface* out) {
    out->desc = &s;
    out->bpp  = bpp;
    if (s.is_fb_pa != 0u) {
        const uint32_t fb_base = fb_->MemBasePa();
        const uint32_t fb_size = fb_->RegionBytes();
        if (s.buffer < fb_base) return false;
        const uint32_t off = s.buffer - fb_base;
        if (off >= fb_size) return false;
        out->host_lo   = fb_->Bytes();
        out->host_hi   = fb_->Bytes() + fb_size;
        out->host_base = fb_->Bytes() + off;
    } else {
        uint8_t* span = arena_->At(s.stage_off, s.stage_len);
        if (!span) return false;
        out->host_lo   = span;
        out->host_hi   = span + s.stage_len;
        out->host_base = span - (int32_t)(s.stage_off - s.buffer);
    }
    return true;
}

inline uint8_t* BltSurfaceAccess::RotatedPixelPtr(const Surface& s, int32_t x,
                                                  int32_t y) {
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
    uint8_t* p = s.host_base + off;
    if (p < s.host_lo || p + s.bpp > s.host_hi) return nullptr;
    return p;
}

inline uint8_t* BltSurfaceAccess::PixelPtr(const Surface& s, int32_t x, int32_t y,
                                           uint32_t run_bytes, uint32_t* run) {
    if (s.desc->is_rotate) {
        uint8_t* p = RotatedPixelPtr(s, x, y);
        if (!p) return nullptr;
        *run = s.bpp;
        return p;
    }
    const uint32_t off = (uint32_t)y * (uint32_t)s.desc->stride + (uint32_t)x * s.bpp;
    uint8_t* p = s.host_base + off;
    if (p < s.host_lo || p + s.bpp > s.host_hi) return nullptr;
    const uint32_t avail = (uint32_t)(s.host_hi - p);
    *run = run_bytes < avail ? run_bytes : avail;
    return p;
}

inline uint32_t BltSurfaceAccess::ReadStraddlePixel(const Surface& s, int32_t x,
                                                    int32_t y, uint32_t bpp) {
    const uint32_t off = (uint32_t)y * (uint32_t)s.desc->stride + (uint32_t)x * bpp;
    uint8_t* p = s.host_base + off;
    if (p < s.host_lo || p + bpp > s.host_hi) FatalStraddle(s, x, y, off);
    return BltPixelOps::ReadPixel(p, bpp);
}

inline void BltSurfaceAccess::WriteStraddlePixel(const Surface& s, int32_t x,
                                                 int32_t y, uint32_t bpp,
                                                 uint32_t value) {
    const uint32_t off = (uint32_t)y * (uint32_t)s.desc->stride + (uint32_t)x * bpp;
    uint8_t* p = s.host_base + off;
    if (p < s.host_lo || p + bpp > s.host_hi) FatalStraddle(s, x, y, off);
    BltPixelOps::WritePixel(p, bpp, value);
}

inline bool BltSurfaceAccess::ReadSubBytePixel(const Surface& s, int32_t x,
                                               int32_t y, uint32_t bits,
                                               uint32_t* out) {
    const uint32_t bit_x = (uint32_t)x * bits;
    uint32_t run = 0;
    uint8_t* p = PixelPtr(s, (int32_t)(bit_x >> 3), y, 1u, &run);
    if (!p) return false;
    *out = (uint32_t)((*p >> lcd_pixel::MsbFirstShift(bit_x, bits)) & ((1u << bits) - 1u));
    return true;
}

inline bool BltSurfaceAccess::WriteSubBytePixel(const Surface& s, int32_t x,
                                                int32_t y, uint32_t bits,
                                                uint32_t value) {
    const uint32_t bit_x = (uint32_t)x * bits;
    uint32_t run = 0;
    uint8_t* p = PixelPtr(s, (int32_t)(bit_x >> 3), y, 1u, &run);
    if (!p) return false;
    const uint32_t shift = lcd_pixel::MsbFirstShift(bit_x, bits);
    const uint8_t  mask  = (uint8_t)(((1u << bits) - 1u) << shift);
    *p = (uint8_t)((*p & ~mask) | ((value << shift) & mask));
    return true;
}

}
