#pragma once

#include <cstdint>

namespace CerfVirt {

/* BLT_ALPHABLEND compositing, faithful to WINCE600 GPE swblt.cpp:968-1234.
   AlphaContext is built once per blit; Blend runs per pixel. Premultiplied
   only — non-premultiplied src (AlphaFormat not 0 and not AC_SRC_ALPHA) is
   rejected by the blitter before reaching here (swblt.cpp:267-272). */

const uint32_t kBltAlphaSrcNeg  = 0x0040u; /* BLT_ALPHASRCNEG  (winddi.h BlendFlags) */
const uint32_t kBltAlphaDestNeg = 0x0080u; /* BLT_ALPHADESTNEG */
const uint8_t  kAcSrcAlpha      = 0x01u;   /* AC_SRC_ALPHA */

struct BltAlphaContext {
    uint32_t red_mask, green_mask, blue_mask, alpha_mask;
    uint32_t red_shift, green_shift, blue_shift, alpha_shift;
    uint32_t src_alpha_mask, src_alpha_shift;
    uint8_t  const_alpha;     /* BLENDFUNCTION.SourceConstantAlpha */
    uint8_t  alpha_format;    /* 0 = constant-only; AC_SRC_ALPHA = per-pixel */
    uint32_t blend_flags;     /* SRCNEG / DESTNEG */
};

struct BltAlpha {

    static uint32_t ShiftOf(uint32_t mask) {
        uint32_t bit = 0;
        if (!mask) return 0;
        while (!(mask & 1u)) { mask >>= 1; ++bit; }
        return bit;
    }

    /* src MUST already be pLookup+pConvert'd to dst format (swblt.cpp:798-806)
       before Blend: red/green/blue/alpha masks are the DST format's, applied to
       both src and dst. original_src is the pre-conversion source, read with the
       SRC-format src_alpha_mask for per-pixel alpha (swblt.cpp:1015). */
    static uint32_t Blend(const BltAlphaContext& c, uint32_t src, uint32_t dst,
                          uint32_t original_src) {
        uint32_t SrcRed   = (src & c.red_mask)   >> c.red_shift;
        uint32_t SrcGreen = (src & c.green_mask) >> c.green_shift;
        uint32_t SrcBlue  = (src & c.blue_mask)  >> c.blue_shift;
        uint32_t SrcAlpha = (src & c.alpha_mask) >> c.alpha_shift;

        uint32_t DstRed   = (dst & c.red_mask)   >> c.red_shift;
        uint32_t DstGreen = (dst & c.green_mask) >> c.green_shift;
        uint32_t DstBlue  = (dst & c.blue_mask)  >> c.blue_shift;
        uint32_t DstAlpha = (dst & c.alpha_mask) >> c.alpha_shift;

        uint8_t  Alpha = c.const_alpha;
        int      AlphaType = 0;

        if (c.alpha_format) {
            SrcAlpha = (original_src & c.src_alpha_mask) >> c.src_alpha_shift;
            if (SrcAlpha == 0u) {
                return (DstRed << 16) | (DstGreen << 8) | DstBlue | (DstAlpha << 24);
            } else if (SrcAlpha == 255u && Alpha == 255u) {
                return (SrcRed << 16) | (SrcGreen << 8) | SrcBlue | (SrcAlpha << 24);
            } else if (SrcAlpha == 255u) {
                AlphaType = 1;
            } else {
                AlphaType = (Alpha == 255u) ? 2 : 3;
            }
        } else {
            AlphaType = 1;
        }

        if (c.blend_flags & kBltAlphaSrcNeg) {
            SrcAlpha = (uint8_t)(c.alpha_mask >> c.alpha_shift) - SrcAlpha;
            Alpha    = (uint8_t)((c.alpha_mask >> c.alpha_shift) - Alpha);
        }
        if (c.blend_flags & kBltAlphaDestNeg) {
            DstAlpha = (uint8_t)(c.alpha_mask >> c.alpha_shift) - DstAlpha;
        }

        uint32_t out;
        if (AlphaType == 3) {
            uint32_t uB00aa00gg = (SrcAlpha << 16) | SrcGreen;
            uint32_t uB00rr00bb = (SrcRed   << 16) | SrcBlue;
            uint32_t uTaaaagggg = uB00aa00gg * Alpha + 0x00800080u;
            uint32_t uTrrrrbbbb = uB00rr00bb * Alpha + 0x00800080u;
            uint32_t uT00aa00gg = (uTaaaagggg & 0xff00ff00u) >> 8;
            uint32_t uT00rr00bb = (uTrrrrbbbb & 0xff00ff00u) >> 8;
            uint32_t uCaa00gg00 = ((uTaaaagggg + uT00aa00gg) & 0xff00ff00u);
            uint32_t uC00rr00bb = ((uTrrrrbbbb + uT00rr00bb) & 0xff00ff00u) >> 8;
            out = uCaa00gg00 | uC00rr00bb;

            uint8_t beta = 255u - (uint8_t)((out & 0xff000000u) >> 24);
            uint32_t _D1_00aa00gg = (DstAlpha << 16) | DstGreen;
            uint32_t _D1_00rr00bb = (DstRed   << 16) | DstBlue;
            uint32_t _D2_aaaagggg = _D1_00aa00gg * beta + 0x00800080u;
            uint32_t _D2_rrrrbbbb = _D1_00rr00bb * beta + 0x00800080u;
            uint32_t _D3_00aa00gg = (_D2_aaaagggg & 0xff00ff00u) >> 8;
            uint32_t _D3_00rr00bb = (_D2_rrrrbbbb & 0xff00ff00u) >> 8;
            uint32_t _D4_00aa00gg = ((_D2_aaaagggg + _D3_00aa00gg) & 0xff00ff00u) >> 8;
            uint32_t _D4_00rr00bb = ((_D2_rrrrbbbb + _D3_00rr00bb) & 0xff00ff00u) >> 8;
            uint32_t _D5_00aa00gg = _D4_00aa00gg + ((out & 0xff00ff00u) >> 8);
            uint32_t _D5_00rr00bb = _D4_00rr00bb + (out & 0x00ff00ffu);
            out = (_D5_00aa00gg << 8) | _D5_00rr00bb;
        } else if (AlphaType == 2) {
            uint32_t Multa = 255u - SrcAlpha;
            uint32_t _D1_00aa00gg = (DstAlpha << 16) | DstGreen;
            uint32_t _D1_00rr00bb = (DstRed   << 16) | DstBlue;
            uint32_t _D2_aaaagggg = _D1_00aa00gg * Multa + 0x00800080u;
            uint32_t _D2_rrrrbbbb = _D1_00rr00bb * Multa + 0x00800080u;
            uint32_t _D3_00aa00gg = (_D2_aaaagggg & 0xff00ff00u) >> 8;
            uint32_t _D3_00rr00bb = (_D2_rrrrbbbb & 0xff00ff00u) >> 8;
            uint32_t _D4_00aa00gg = ((_D2_aaaagggg + _D3_00aa00gg) & 0xff00ff00u) >> 8;
            uint32_t _D4_00rr00bb = ((_D2_rrrrbbbb + _D3_00rr00bb) & 0xff00ff00u) >> 8;
            uint32_t _D5_00aa00gg = _D4_00aa00gg + ((SrcAlpha << 16) | SrcGreen);
            uint32_t _D5_00rr00bb = _D4_00rr00bb + ((SrcRed   << 16) | SrcBlue);
            out = (_D5_00aa00gg << 8) | _D5_00rr00bb;
        } else { /* AlphaType == 1: constant alpha only */
            uint32_t uB00rr00bb = (DstRed << 16) | DstBlue;
            uint32_t uF00rr00bb = (SrcRed << 16) | SrcBlue;
            uint32_t uMrrrrbbbb = ((uB00rr00bb << 8) - uB00rr00bb)
                                + (Alpha * (uF00rr00bb - uB00rr00bb)) + 0x00800080u;
            uint32_t uM00rr00bb = (uMrrrrbbbb & 0xff00ff00u) >> 8;
            uint32_t uD00rr00bb = ((uMrrrrbbbb + uM00rr00bb) & 0xff00ff00u) >> 8;

            uint32_t uB00aa00gg = (DstAlpha << 16) | DstGreen;
            uint32_t uF00aa00gg = (SrcAlpha << 16) | SrcGreen;
            uint32_t uMaaaagggg = ((uB00aa00gg << 8) - uB00aa00gg)
                                + (Alpha * (uF00aa00gg - uB00aa00gg)) + 0x00800080u;
            uint32_t uM00aa00gg = (uMaaaagggg & 0xff00ff00u) >> 8;
            uint32_t uDaa00gg00 = (uMaaaagggg + uM00aa00gg) & 0xff00ff00u;

            out = uD00rr00bb + uDaa00gg00;
        }
        return out;
    }
};

}  /* namespace CerfVirt */
