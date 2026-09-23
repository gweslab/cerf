#pragma once

#include "../../core/byte_order.h"

#include <cstdint>

namespace CerfVirt {

struct BltPixelOps {

    static uint32_t ProcessRop3(uint32_t dst, uint32_t src, uint32_t brush,
                                uint8_t rop3, uint8_t dst_bpp) {
        if (dst_bpp > 24u) {
            return ProcessRop3(dst, src, brush, rop3, 16u)
                 | (ProcessRop3(dst >> 16, src >> 16, brush >> 16, rop3,
                                (uint8_t)(dst_bpp - 16u)) << 16);
        }
        uint32_t result = 0u, result_bit = 1u;
        brush <<= 2;
        src   <<= 1;
        while (dst_bpp--) {
            if ((1u << ((brush & 4u) | (src & 2u) | (dst & 1u))) & rop3) {
                result |= result_bit;
            }
            brush >>= 1;
            src   >>= 1;
            dst   >>= 1;
            result_bit <<= 1;
        }
        return result;
    }

    static uint32_t ApplyRop3(uint8_t rop3, uint32_t src, uint32_t dst,
                              uint32_t brush, uint8_t dst_bpp) {
        switch (rop3) {
        case 0xAA: return src;
        case 0xCC: return src;
        case 0x00: return 0u;
        case 0x22: return (~src) & dst;
        case 0xB8: return (brush & ~src) | (src & dst);
        case 0x11: return ~(src | dst);
        case 0x33: return ~src;
        case 0x44: return src & ~dst;
        case 0x55: return ~dst;
        case 0x5A: return brush ^ dst;
        case 0x66: return src ^ dst;
        case 0x88: return src & dst;
        case 0xBB: return ~src | dst;
        case 0xC0: return src & brush;
        case 0xEE: return src | dst;
        case 0xF0: return brush;
        case 0xFB: return brush | ~src | dst;
        case 0xFF: return 0xFFFFFFFFu;
        case 0xE2: return (dst & ~src) | (brush & src);
        case 0xAC: return ((src ^ dst) & brush) ^ src;
        default:   return ProcessRop3(dst, src, brush, rop3, dst_bpp);
        }
    }

    static uint32_t ApplyRop2(uint8_t rop2, uint32_t P, uint32_t D) {
        switch (rop2) {
        case 1:  return 0u;
        case 2:  return ~(P | D);
        case 3:  return ~P & D;
        case 4:  return ~P;
        case 5:  return P & ~D;
        case 6:  return ~D;
        case 7:  return P ^ D;
        case 8:  return ~(P & D);
        case 9:  return P & D;
        case 10: return ~(P ^ D);
        case 11: return D;
        case 12: return ~P | D;
        case 13: return P;
        case 14: return P | ~D;
        case 15: return P | D;
        case 16: return 0xFFFFFFFFu;
        default: return D;
        }
    }

    static bool DestMatters(uint32_t rop4) {
        const uint8_t fg = (uint8_t)rop4;
        const uint8_t bg = (uint8_t)(rop4 >> 8);
        return (((fg >> 1) ^ fg) & 0x55u) != 0u
            || (((bg >> 1) ^ bg) & 0x55u) != 0u;
    }

    static uint32_t FormatBits(uint32_t fmt) {
        static const uint32_t b[7] = { 1u, 2u, 4u, 8u, 16u, 24u, 32u };
        return fmt < 7u ? b[fmt] : 0u;
    }

    static uint32_t HighBitPos(uint32_t m) { uint32_t p = 0; while (m) { ++p; m >>= 1; } return p; }
    static uint32_t PopCount(uint32_t m)   { uint32_t c = 0; while (m) { c += m & 1u; m >>= 1; } return c; }

    static uint32_t ConvertPixel(uint32_t sp,
            const uint32_t s_mask[3], const uint32_t s_shift[3], const uint32_t s_bits[3],
            const uint32_t d_mask[3], const uint32_t d_shift[3]) {
        uint32_t r = (sp & s_mask[0]) << s_shift[0]; r |= r >> s_bits[0];
        uint32_t g = (sp & s_mask[1]) << s_shift[1]; g |= g >> s_bits[1];
        uint32_t b = (sp & s_mask[2]) << s_shift[2]; b |= b >> s_bits[2];
        const uint32_t canon = (r >> 24) | ((g >> 16) & 0x0000FF00u) | ((b >> 8) & 0x00FF0000u);
        return (((canon << 24) >> d_shift[0]) & d_mask[0])
             | (((canon << 16) >> d_shift[1]) & d_mask[1])
             | (((canon << 8 ) >> d_shift[2]) & d_mask[2]);
    }

    static bool FormatMasks(uint32_t fmt, uint32_t masks[3], uint32_t* bpp) {
        switch (fmt) {
        case 4: masks[0]=0xF800u;     masks[1]=0x07E0u;     masks[2]=0x001Fu;     *bpp=2; return true;
        case 5: masks[0]=0x00FF0000u; masks[1]=0x0000FF00u; masks[2]=0x000000FFu; *bpp=3; return true;
        case 6: masks[0]=0x00FF0000u; masks[1]=0x0000FF00u; masks[2]=0x000000FFu; *bpp=4; return true;
        default: return false;
        }
    }

    static uint32_t ReadPixel(const uint8_t* p, uint32_t bpp) {
        return static_cast<uint32_t>(cerf::le::UN(p, bpp));
    }
    static void WritePixel(uint8_t* p, uint32_t bpp, uint32_t v) { cerf::le::PutN(p, v, bpp); }
};

}
