#include "mediaq_mq200_ge.h"

#include "../../core/byte_order.h"
#include "../../core/log.h"

const MediaQGe::Layout& MediaQMq200Ge::Lyt() const {
    /* fg=GE42R, bg=GE43R, pat_fg=GE42R; src_stride=GE09R; GE0AR stride[11:0]
       (Table 5-73), GE0BR base[20:0] (Table 5-74). */
    static const Layout kL{0x42u, 0x43u, 0x42u, 0x09u, 0xFFFu, 0x1FFFFFu,
                           0x43u, 0x40u, 0x41u, 0x40u};
    return kL;
}

/* ddi.dll's rectangle fill (sub_13458A0 / sub_1345944) issues a BitBLT with
   mono pattern (GE00R[15]) + solid (GE00R[23]); the pattern colour is GE42R. */
bool MediaQMq200Ge::IsSolidFill(uint32_t cmd) const {
    return (cmd & kCmdMonoPat) != 0u && (cmd & kCmdSolidSrc) != 0u;
}

uint32_t MediaQMq200Ge::SolidFillColor() const {
    return reg_[kGe42PatFg];
}

uint32_t MediaQMq200Ge::LineColor(uint32_t cmd) const {
    if ((cmd & kCmdMonoPat) || (cmd & kCmdMonoSrc)) return reg_[kGe42PatFg];
    if (cmd & kCmdSolidSrc) return reg_[kGe07FgColor];
    LOG(Caution, "MediaQ MQ200 GE: non-solid line source (cmd=0x%08X)\n", cmd);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

/* Dwords a system-source blit consumes before it draws. Mono = packed 1-bpp
   bitstream; colour = packed byte stream (see BlitColorSource). */
uint32_t MediaQMq200Ge::ExpectedSourceDwords() const {
    const uint32_t w = reg_[kGe01Size] & 0xFFFu;
    const uint32_t h = (reg_[kGe01Size] >> 16) & 0xFFFu;
    if (w == 0u || h == 0u) return 0u;
    if (reg_[kGe00Command] & kCmdMonoSrc) {
        /* Packed 1-bpp bitstream, byte-aligned rows (GE09R packed: [5:3] byte,
           [2:0] bit initial offset, Data Book Table 5-72); the driver may pad
           the tail, but the blit needs only enough dwords to cover the bits. */
        const uint32_t g09 = reg_[kGe09SrcOff];
        const uint32_t bit_off0 = ((g09 >> 3) & 7u) * 8u + (g09 & 7u);
        const uint32_t stride_bits = ((w + 7u) / 8u) * 8u;
        const uint32_t total_bits = bit_off0 + (h - 1u) * stride_bits + w;
        return (total_bits + 31u) / 32u;
    }
    const uint32_t bpp = BytesPerPixel() ? BytesPerPixel() : 2u;
    const uint32_t g09 = reg_[kGe09SrcOff];
    /* Non-packed CM2SLKBlt16 (gpe4Bpp, ddi.dll sub_1347E64): per row ulDWords =
       ((srcLeft&1)+w)*bpp padded to a 128-bit boundary, h rows; GE09 carries only
       the (srcLeft&1) pixel lead in [29], no byte-space field. */
    if ((reg_[kGe00Command] & kCmdPacked) == 0u) {
        const uint32_t lead_px = (g09 >> 29) & 1u;
        uint32_t dwords = ((lead_px + w) * bpp + 3u) >> 2;
        dwords += (4u - (dwords & 3u)) & 3u;
        return dwords * h;
    }
    const uint32_t offset = (g09 >> 3) & 0x1Fu;
    const uint32_t byte_space = (g09 >> 28) & 0xFu;
    const uint32_t src_bytes = w * bpp;
    const uint32_t total_bytes = offset + (src_bytes + byte_space) * (h - 1u) + src_bytes;
    return (total_bytes + 3u) >> 2;
}

void MediaQMq200Ge::BlitColorSource(const uint32_t* r) {
    const uint32_t bpp    = BytesPerPixel();
    const uint32_t stride = r[kGe0ADstStride] & Lyt().stride_mask;
    const uint32_t base   = r[kGe0BBase] & Lyt().base_mask;
    if (bpp != 2u || stride == 0u) {
        LOG(Caution, "MediaQ MQ200 GE: colour-source blit unsupported depth/stride "
                     "(bpp=%u stride=%u)\n", bpp, stride);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    const uint32_t size = r[kGe01Size];
    const uint32_t w = size & 0xFFFu;
    const uint32_t h = (size >> 16) & 0xFFFu;
    if (w == 0u || h == 0u) return;

    const uint32_t g09        = r[kGe09SrcOff];
    /* PACKED CM2SBlt16 vs non-packed CM2SLKBlt16 (gpe4Bpp, ddi.dll sub_1347E64):
       packed GE09[7:3] = per-row lead bytes, [31:28] = trailing pad; non-packed
       GE09[29] = (srcLeft&1) pixel lead, per-row stride = ulDWords padded to a
       128-bit boundary, no byte-space field. */
    const bool     packed     = (r[kGe00Command] & kCmdPacked) != 0u;
    const uint32_t byte_space = (g09 >> 28) & 0xFu;
    uint32_t offset, row_bytes;
    if (packed) {
        offset    = (g09 >> 3) & 0x1Fu;
        row_bytes = w * bpp + byte_space;
    } else {
        const uint32_t lead_px = (g09 >> 29) & 1u;
        offset = lead_px * bpp;
        uint32_t dwords = ((lead_px + w) * bpp + 3u) >> 2;
        dwords += (4u - (dwords & 3u)) & 3u;
        row_bytes = dwords * 4u;
    }
    const size_t   fifo_bytes = src_fifo_.size() * 4u;

    const uint8_t rop = static_cast<uint8_t>(r[kGe00Command] & kCmdRopMask);

    const uint32_t xy = r[kGe02DstXY];
    const uint32_t dx = xy & 0xFFFu;
    const uint32_t dy = (xy >> 16) & 0xFFFu;

    const bool trans = (r[kGe00Command] & kCmdColorTrans) != 0u;
    const uint32_t key = r[kGe04ColorCmp] & 0xFFFFu;

    uint8_t* const fb     = Fb();
    const uint32_t fbsize = FbBytes();

    for (uint32_t row = 0; row < h; ++row) {
        const uint32_t row_pos = offset + row * row_bytes;
        for (uint32_t col = 0; col < w; ++col) {
            const uint32_t pos = row_pos + col * bpp;
            if (static_cast<size_t>(pos) + bpp > fifo_bytes) break;  /* source under-delivered. */
            const uint32_t px = cerf::le::U16(SrcFifoBytes(), pos);
            if (trans && px == key) continue;
            const uint64_t addr = static_cast<uint64_t>(base) +
                static_cast<uint64_t>(dy + row) * stride +
                static_cast<uint64_t>(dx + col) * bpp;
            RopPixel(fb, fbsize, addr, bpp, 0xFFFFu, rop, PatternOperand(r, col, row), px);
        }
    }
}

/* Mono->colour BitBLT, packed 1-bpp source via Source FIFO (GE00R[20]=1). Bit for
   dest (row,col) = bit_off0 + row*stride_bits + col, MSB-first per byte; bit_off0
   = GE09R[5:3]*8 + [2:0], stride_bits = ceil(w/8)*8 (byte-aligned rows). Set bit
   -> GE42R fg, clear -> GE43R bg. */
void MediaQMq200Ge::BlitMonoSource(const uint32_t* r) {
    const uint32_t bpp    = BytesPerPixel();
    const uint32_t stride = r[kGe0ADstStride] & Lyt().stride_mask;
    const uint32_t base   = r[kGe0BBase] & Lyt().base_mask;
    if (bpp != 2u || stride == 0u) {
        LOG(Caution, "MediaQ MQ200 GE: mono-source blit unsupported depth/stride "
                     "(bpp=%u stride=%u)\n", bpp, stride);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    const uint32_t size = r[kGe01Size];
    const uint32_t w = size & 0xFFFu;
    const uint32_t h = (size >> 16) & 0xFFFu;
    if (w == 0u || h == 0u) return;

    const uint32_t g09 = r[kGe09SrcOff];
    const uint32_t bit_off0 = ((g09 >> 3) & 7u) * 8u + (g09 & 7u);
    const uint32_t stride_bits = ((w + 7u) / 8u) * 8u;
    const uint32_t total_bits = bit_off0 + (h - 1u) * stride_bits + w;
    if (src_fifo_.size() < (total_bits + 31u) / 32u) return;

    const uint8_t  rop = static_cast<uint8_t>(r[kGe00Command] & kCmdRopMask);
    const uint32_t fg  = r[kGe07FgColor] & 0xFFFFu;
    const uint32_t bg  = r[kGe08BgColor] & 0xFFFFu;
    const bool mono_trans  = (r[kGe00Command] & kCmdMonoTrans) != 0u;
    const bool trans_clear = mono_trans && (r[kGe00Command] & kCmdMonoTrPol) == 0u;
    const bool trans_set   = mono_trans && (r[kGe00Command] & kCmdMonoTrPol) != 0u;

    const uint32_t xy = r[kGe02DstXY];
    const uint32_t dx = xy & 0xFFFu;
    const uint32_t dy = (xy >> 16) & 0xFFFu;

    const bool clip = (r[kGe00Command] & kCmdEnClip) != 0u;
    const uint32_t cl = r[kGe05ClipLT] & 0xFFFu;
    const uint32_t ct = (r[kGe05ClipLT] >> 16) & 0xFFFu;
    const uint32_t cr = r[kGe06ClipRB] & 0xFFFu;
    const uint32_t cb = (r[kGe06ClipRB] >> 16) & 0xFFFu;

    const bool     pat_en = (r[kGe00Command] & kCmdMonoPat) != 0u;
    const uint32_t pat_fg = r[kGe42PatFg] & 0xFFFFu;
    const uint32_t pat_bg = r[kGe43PatBg] & 0xFFFFu;
    const uint32_t mono_pat[2] = { r[kGe40MonoPat0], r[kGe41MonoPat1] };

    uint8_t* const fb     = Fb();
    const uint32_t fbsize = FbBytes();

    for (uint32_t row = 0; row < h; ++row) {
        const uint32_t yy = dy + row;
        if (clip && (yy < ct || yy > cb)) continue;
        for (uint32_t col = 0; col < w; ++col) {
            const uint32_t xx = dx + col;
            if (clip && (xx < cl || xx > cr)) continue;
            const uint32_t bit = MonoBit(SrcFifoBytes(), bit_off0 + row * stride_bits + col);
            if (bit && trans_set) continue;
            if (!bit && trans_clear) continue;
            const uint32_t color = bit ? fg : bg;
            const uint64_t addr = static_cast<uint64_t>(base) +
                static_cast<uint64_t>(yy) * stride + static_cast<uint64_t>(xx) * bpp;
            const uint32_t pat = pat_en
                ? MonoPatternPixel(mono_pat[0], mono_pat[1], pat_fg, pat_bg, xx, yy) : 0u;
            RopPixel(fb, fbsize, addr, bpp, 0xFFFFu, rop, pat, color);
        }
    }
}

void MediaQMq200Ge::DrawLine(uint32_t cmd) {
    const uint32_t bpp    = BytesPerPixel();
    const uint32_t stride = DestStrideBytes();
    const uint32_t base   = BaseAddr();
    if (bpp == 0u || stride == 0u) {
        LOG(Caution, "MediaQ MQ200 GE: line draw unsupported depth/stride "
                     "(GE0AR=0x%08X)\n", reg_[kGe0ADstStride]);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t pmask = cerf::ByteWidthMask(bpp);

    const uint32_t ge01 = reg_[kGe01Size];    /* LINE_DRAW   */
    const uint32_t ge02 = reg_[kGe02DstXY];   /* LINE_MAJOR_X */
    const uint32_t ge03 = reg_[kGe03SrcXY];   /* LINE_MINOR_Y */

    auto s17 = [](uint32_t v) -> long {
        v &= 0x1FFFFu;
        return (v & 0x10000u) ? static_cast<long>(v) - 0x20000 : static_cast<long>(v);
    };

    int x = static_cast<int>(ge02 & 0xFFFu);          /* start X */
    int y = static_cast<int>(ge03 & 0xFFFu);          /* start Y */
    const uint32_t cPels = (ge01 >> 17) & 0xFFFu;     /* major-axis pixel count */
    const bool y_major   = (ge01 & 0x20000000u) != 0u;/* GE01R[29] = Y_MAJOR */
    const long gamma = s17(ge01 & 0x1FFFFu);          /* GE01R[16:0] error term */
    const long dM = s17((ge02 >> 12) & 0x1FFFFu);     /* GE02R[28:12] major delta */
    const long dN = s17((ge03 >> 12) & 0x1FFFFu);     /* GE03R[28:12] minor delta */
    const int step_x = (cmd & 0x800u)  ? -1 : 1;      /* GE00R X_DIR */
    const int step_y = (cmd & 0x1000u) ? -1 : 1;      /* GE00R Y_DIR */

    uint8_t rop = static_cast<uint8_t>(cmd & kCmdRopMask);
    if (cmd & kCmdRop2)
        rop = static_cast<uint8_t>((cmd & 0x0Fu) | ((cmd & 0x0Fu) << 4));
    const uint32_t color = reg_[kGe07FgColor] & pmask;

    const bool clip = (cmd & kCmdEnClip) != 0u;
    const int cl = static_cast<int>(reg_[kGe05ClipLT] & 0xFFFu);
    const int ct = static_cast<int>((reg_[kGe05ClipLT] >> 16) & 0xFFFu);
    const int cr = static_cast<int>(reg_[kGe06ClipRB] & 0xFFFu);
    const int cb = static_cast<int>((reg_[kGe06ClipRB] >> 16) & 0xFFFu);

    uint8_t* const fb     = Fb();
    const uint32_t fbsize = FbBytes();

    long accum = dN + gamma;
    const long axstp = dN;
    const long dgstp = dN - dM;
    for (uint32_t i = 0; i < cPels; ++i) {
        if (x >= 0 && y >= 0 && !(clip && (x < cl || x > cr || y < ct || y > cb)))
            RopPixel(fb, fbsize, static_cast<uint64_t>(base) +
                     static_cast<uint64_t>(y) * stride + static_cast<uint64_t>(x) * bpp,
                     bpp, pmask, rop, 0u, color);
        if (i + 1u >= cPels) break;
        if (y_major) y += step_y; else x += step_x;   /* major-axis step */
        if (axstp != 0) {
            if (accum < 0) accum += axstp;
            else { if (y_major) x += step_x; else y += step_y; accum += dgstp; }
        }
    }
}
