#pragma once

#include <cstdint>

namespace CerfVirt {

/* Pure pixel math for the host GPE blit pipeline: ROP3 evaluation, CE6 format
   conversion, packed pixel read/write. Header-inline (hot inner loop). */
struct BltPixelOps {

    /* General 256-ROP3 evaluator (blthelpers.cpp ProcessROP3): per color-bit
       plane, index the rop3 truth table by (brush<<2)|(src<<1)|dst. Split above
       24bpp so the brush<<2 below cannot overflow the result lane. */
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

    /* Apply one ROP3 to (src,dst,brush), returning the new src.Value. Named fast
       cases are swblt.cpp:940-966; default falls to ProcessRop3 for the rest of
       the 256 ops. Caller masks the result to dst.Mask. */
    static uint32_t ApplyRop3(uint8_t rop3, uint32_t src, uint32_t dst,
                              uint32_t brush, uint8_t dst_bpp) {
        switch (rop3) {
        case 0xAA: return src;                                   /* NOP (caller skips) */
        case 0xCC: return src;                                   /* SRCCOPY */
        case 0x00: return 0u;                                    /* BLACKNESS */
        case 0x22: return (~src) & dst;
        case 0xB8: return (brush & ~src) | (src & dst);
        case 0x11: return ~(src | dst);                          /* NOTSRCERASE */
        case 0x33: return ~src;                                  /* NOTSRCCOPY */
        case 0x44: return src & ~dst;                            /* SRCERASE */
        case 0x55: return ~dst;                                  /* DSTINVERT */
        case 0x5A: return brush ^ dst;                           /* PATINVERT */
        case 0x66: return src ^ dst;                             /* SRCINVERT */
        case 0x88: return src & dst;                             /* SRCAND */
        case 0xBB: return ~src | dst;                            /* MERGEPAINT */
        case 0xC0: return src & brush;                           /* MERGECOPY */
        case 0xEE: return src | dst;                             /* SRCPAINT */
        case 0xF0: return brush;                                 /* PATCOPY */
        case 0xFB: return brush | ~src | dst;                    /* PATPAINT */
        case 0xFF: return 0xFFFFFFFFu;                           /* WHITENESS */
        case 0xE2: return (dst & ~src) | (brush & src);
        case 0xAC: return ((src ^ dst) & brush) ^ src;
        default:   return ProcessRop3(dst, src, brush, rop3, dst_bpp);
        }
    }

    /* True if the ROP3 reads the destination (swblt.cpp DestMatters): any rop
       whose truth table differs when the dst bit flips. */
    static bool DestMatters(uint32_t rop4) {
        const uint8_t fg = (uint8_t)rop4;
        const uint8_t bg = (uint8_t)(rop4 >> 8);
        return (((fg >> 1) ^ fg) & 0x55u) != 0u
            || (((bg >> 1) ^ bg) & 0x55u) != 0u;
    }

    /* EGPEFormat -> bits per pixel (gpe1Bpp..gpe32Bpp). */
    static uint32_t FormatBits(uint32_t fmt) {
        static const uint32_t b[7] = { 1u, 2u, 4u, 8u, 16u, 24u, 32u };
        return fmt < 7u ? b[fmt] : 0u;
    }

    static uint32_t HighBitPos(uint32_t m) { uint32_t p = 0; while (m) { ++p; m >>= 1; } return p; }
    static uint32_t PopCount(uint32_t m)   { uint32_t c = 0; while (m) { c += m & 1u; m >>= 1; } return c; }

    /* CE6 GPE MaskColorConverter (swconvrt.cpp): align each channel's mask top
       bit to bit31, replicate downward (|= >> bits) so 5-bit 0x1F -> 0xFF, pack
       to canonical 0x00BBGGRR, invert into dst masks. */
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

    /* EGPEFormat -> {R,G,B} masks + bytes-per-pixel (device 565/888, matches
       DrvGetMasks). Returns false for sub-byte formats handled by the bit-cache
       reader, not the byte reader. */
    static bool FormatMasks(uint32_t fmt, uint32_t masks[3], uint32_t* bpp) {
        switch (fmt) {
        case 4: masks[0]=0xF800u;     masks[1]=0x07E0u;     masks[2]=0x001Fu;     *bpp=2; return true;
        case 5: masks[0]=0x00FF0000u; masks[1]=0x0000FF00u; masks[2]=0x000000FFu; *bpp=3; return true;
        case 6: masks[0]=0x00FF0000u; masks[1]=0x0000FF00u; masks[2]=0x000000FFu; *bpp=4; return true;
        default: return false;
        }
    }

    static uint32_t ReadPixel(const uint8_t* p, uint32_t bpp) {
        if (bpp == 2) return *reinterpret_cast<const uint16_t*>(p);
        if (bpp == 4) return *reinterpret_cast<const uint32_t*>(p);
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
    }
    static void WritePixel(uint8_t* p, uint32_t bpp, uint32_t v) {
        if (bpp == 2) { *reinterpret_cast<uint16_t*>(p) = (uint16_t)v; return; }
        if (bpp == 4) { *reinterpret_cast<uint32_t*>(p) = v; return; }
        p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16);
    }
};

}  /* namespace CerfVirt */
