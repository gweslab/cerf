#include "mediaq_mq1188_ge.h"

#include "../../core/byte_order.h"
#include "../../core/log.h"

/* Colour BitBLT, source streamed through the Source FIFO (ddi.dll sub_1845A9C):
   16-bpp pixels two per dword, height rows of dwordsPerRow each; first valid
   pixel of every row at sub-dword offset GE09R bit 4 (= srcLeft & 1). */
void MediaQMq1188Ge::BlitColorSource(const uint32_t* r) {
    const uint32_t bpp    = BytesPerPixel();
    const uint32_t stride = r[kGe0ADstStride] & Lyt().stride_mask;
    const uint32_t base   = r[kGe0BBase] & Lyt().base_mask;
    if (bpp != 2u || stride == 0u) {
        LOG(Caution, "MediaQ MQ1188 GE: colour-source blit unsupported depth/stride "
                     "(bpp=%u stride=%u)\n", bpp, stride);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    const uint32_t size = r[kGe01Size];
    const uint32_t w = size & 0xFFFu;
    const uint32_t h = (size >> 16) & 0xFFFu;
    if (w == 0u || h == 0u) return;
    if (src_fifo_.size() < static_cast<size_t>(h)) return;

    const uint32_t dwords_per_row = static_cast<uint32_t>(src_fifo_.size()) / h;
    const uint32_t start_px = (r[kGe09SrcStride] >> 4) & 1u;  /* GE09R bit 4. */
    const uint8_t  rop = static_cast<uint8_t>(r[kGe00Command] & kCmdRopMask);

    const uint32_t xy = r[kGe02DstXY];
    const uint32_t dx = xy & 0xFFFu;
    const uint32_t dy = (xy >> 16) & 0xFFFu;

    const bool trans = (r[kGe00Command] & kCmdColorTrans) != 0u;
    const uint32_t key = r[kGe04ColorCmp] & 0xFFFFu;

    uint8_t* const fb     = Fb();
    const uint32_t fbsize = FbBytes();

    for (uint32_t row = 0; row < h; ++row) {
        const uint8_t* line = SrcFifoBytes() + static_cast<size_t>(row) * dwords_per_row * 4u;
        if ((start_px + w + 1u) / 2u > dwords_per_row) break;  /* malformed stream. */
        for (uint32_t col = 0; col < w; ++col) {
            const uint32_t px = cerf::le::U16(line, (start_px + col) * 2u);
            if (trans && px == key) continue;
            const uint64_t addr = static_cast<uint64_t>(base) +
                static_cast<uint64_t>(dy + row) * stride +
                static_cast<uint64_t>(dx + col) * bpp;
            RopPixel(fb, fbsize, addr, bpp, 0xFFFFu, rop, PatternOperand(r, col, row), px);
        }
    }
}

/* Mono->colour BitBLT, 1-bpp source streamed via the Source FIFO. Source bit for
   dest (row,col) is bitOff0 + row*strideBits + col, MSB-first within each byte;
   bitOff0 = GE09R[4:0], strideBits = width + GE09R[31:25] (ddi.dll sub_184550C).
   Set bit -> GE07R fg, clear -> GE08R bg. */
void MediaQMq1188Ge::BlitMonoSource(const uint32_t* r) {
    const uint32_t bpp    = BytesPerPixel();
    const uint32_t stride = r[kGe0ADstStride] & Lyt().stride_mask;
    const uint32_t base   = r[kGe0BBase] & Lyt().base_mask;
    if (bpp != 2u || stride == 0u) {
        LOG(Caution, "MediaQ MQ1188 GE: mono-source blit unsupported depth/stride "
                     "(bpp=%u stride=%u)\n", bpp, stride);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    const uint32_t size = r[kGe01Size];
    const uint32_t w = size & 0xFFFu;
    const uint32_t h = (size >> 16) & 0xFFFu;
    if (w == 0u || h == 0u) return;

    const uint32_t g09 = r[kGe09SrcStride];
    const uint32_t bit_off0 = g09 & 0x1Fu;
    const uint32_t stride_bits = w + (g09 >> 25);

    const uint32_t total_bits = bit_off0 + (h - 1u) * stride_bits + w;
    const uint32_t need_dw = (total_bits + 31u) / 32u;
    if (src_fifo_.size() < need_dw) {
        LOG(Caution, "MediaQ MQ1188 GE: mono-source general-path layout not implemented "
                     "(have=%zu need=%u w=%u h=%u sb=%u off=%u)\n",
            src_fifo_.size(), need_dw, w, h, stride_bits, bit_off0);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    const uint8_t  rop = static_cast<uint8_t>(r[kGe00Command] & kCmdRopMask);
    const uint32_t fg  = r[kGe07FgColor] & 0xFFFFu;
    const uint32_t bg  = r[kGe08BgColor] & 0xFFFFu;
    const bool mono_trans  = (r[kGe00Command] & kCmdMonoTrans) != 0u;
    const bool trans_clear = mono_trans && (r[kGe00Command] & kCmdMonoTrPol) == 0u;
    const bool trans_set   = mono_trans && (r[kGe00Command] & kCmdMonoTrPol) != 0u;

    const uint32_t xy = r[kGe02DstXY];
    const uint32_t dx = xy & 0xFFFu;
    const uint32_t dy = (xy >> 16) & 0xFFFu;

    /* GE00R[15]=MONO_PATTERN supplies the ROP's P operand (PAT_FG/PAT_BG via the
       8x8 pattern). Drop it and rop=0xB8 imagelist icons collapse to black
       (ddi.dll sub_18437D4 programs MONO_PATTERN0/1 + PAT_FG for the brush). */
    const bool     pat_en = (r[kGe00Command] & kCmdMonoPat) != 0u;
    const uint32_t pat_fg = r[kGe12PatFg] & 0xFFFFu;
    const uint32_t pat_bg = r[kGe13PatBg] & 0xFFFFu;
    const uint32_t mono_pat[2] = { r[kGe10MonoPat0], r[kGe11MonoPat1] };

    uint8_t* const fb     = Fb();
    const uint32_t fbsize = FbBytes();

    for (uint32_t row = 0; row < h; ++row) {
        for (uint32_t col = 0; col < w; ++col) {
            const uint32_t bit = MonoBit(SrcFifoBytes(), bit_off0 + row * stride_bits + col);
            if (bit && trans_set) continue;
            if (!bit && trans_clear) continue;
            const uint32_t color = bit ? fg : bg;
            const uint64_t addr = static_cast<uint64_t>(base) +
                static_cast<uint64_t>(dy + row) * stride +
                static_cast<uint64_t>(dx + col) * bpp;
            const uint32_t pat = pat_en
                ? MonoPatternPixel(mono_pat[0], mono_pat[1], pat_fg, pat_bg, dx + col, dy + row) : 0u;
            RopPixel(fb, fbsize, addr, bpp, 0xFFFFu, rop, pat, color);
        }
    }
}
