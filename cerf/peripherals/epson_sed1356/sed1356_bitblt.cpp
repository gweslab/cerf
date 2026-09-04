#include "sed1356_bitblt.h"

#include "sed1356.h"
#include "../../state/state_stream.h"

#include <cstring>
#include <vector>

namespace {

/* Mono bit-stream order within a data word (Programming Notes §10.2.2
   examples 1-4): low byte bit7..bit0, then high byte bit7..bit0. */
uint32_t MonoBitOfWord(uint16_t word, uint32_t pos) {
    const uint32_t shift = (pos < 8u) ? (7u - pos) : (23u - pos);
    return (word >> shift) & 1u;
}

}  /* namespace */

void Sed1356BitBlt::Start() {
    auto R = [&](uint32_t o) { return (uint32_t)owner_.BltReg(o); };

    p_ = {};
    p_.op    = (uint8_t)(R(0x103) & 0xFu);          /* Table 8-32.        */
    p_.rop   = (uint8_t)(R(0x102) & 0xFu);          /* Table 10-1.        */
    p_.bpp16 = (R(0x101) & 0x1u) != 0;              /* REG[101h] bit 0.   */
    p_.px    = p_.bpp16 ? 2u : 1u;
    p_.src   = R(0x104) | R(0x105) << 8 | (R(0x106) & 0x1Fu) << 16;
    p_.dst   = R(0x108) | R(0x109) << 8 | (R(0x10A) & 0x1Fu) << 16;
    p_.width  = ((R(0x111) & 0x3u) << 8 | R(0x110)) + 1u;
    p_.height = ((R(0x113) & 0x3u) << 8 | R(0x112)) + 1u;
    p_.bg = (uint16_t)(R(0x114) | R(0x115) << 8);
    p_.fg = (uint16_t)(R(0x118) | R(0x119) << 8);

    /* REG[10Ch/10Dh] line offset is in words; the linear selects collapse a
       rect into a contiguous run (Programming Notes §10.1). */
    const uint32_t offset_bytes = (((R(0x10D) & 0x7u) << 8) | R(0x10C)) * 2u;
    const uint32_t ctl = R(0x100);
    p_.dst_stride = (ctl & 0x2u) ? p_.width * p_.px : offset_bytes;
    p_.src_stride = (ctl & 0x1u) ? p_.width * p_.px : offset_bytes;

    in_fifo_.clear();
    out_fifo_.clear();
    cpu_op_active_  = false;
    words_per_line_ = 0;
    lines_done_     = 0;
    read_line_      = 0;

    switch (p_.op) {
        case kWriteRop:
        case kTransparentWrite:
        case kColorExpand:
        case kColorExpandTransp:
            cpu_op_active_  = true;
            words_per_line_ = WordsPerLine();
            in_fifo_.reserve(words_per_line_);
            return;
        case kRead:
            RenderReadFifo();
            return;
        case kMovePosRop:
        case kMoveNegRop:
        case kTransparentMovePos:
        case kPatternFillRop:
        case kPatternFillTransp:
        case kMoveColorExpand:
        case kMoveColorExpandTr:
        case kSolidFill:
            ExecuteDisplayOp();
            return;
        default:
            owner_.HaltUnsupportedAccess("BitBlt reserved operation",
                                         owner_.MmioBase() + 0x103u, p_.op);
    }
}

/* Table 8-30 word count -> depth bits: 0 empty, 1-6 not-empty, 7-14 +half
   full, 15-16 +full. The count is out_fifo_ alone, per §10.2 (p. 68): "If the
   S1D13506 empties the FIFO faster than the CPU can fill it, it may not be
   possible to cause an overflow/underflow." */
uint8_t Sed1356BitBlt::Status() const {
    uint8_t s = (uint8_t)(owner_.reg_[0x100] & 0x3u);
    if (cpu_op_active_ || !out_fifo_.empty()) s |= 0x80u;   /* busy.      */
    const size_t n = out_fifo_.size();
    if (n >= 1u)  s |= 0x40u;
    if (n >= 7u)  s |= 0x20u;
    if (n >= 15u) s |= 0x10u;
    return s;
}

void Sed1356BitBlt::DataWrite(uint16_t value) {
    if (!cpu_op_active_)
        owner_.HaltUnsupportedAccess("BitBlt data write with no CPU-fed "
                                     "operation active",
                                     owner_.MmioBase() + 0x100000u, value);
    in_fifo_.push_back(value);
    /* Programming Notes §10.2 (p. 68): "While the FIFO is being written to by
       the CPU, it is also being emptied by the S1D13506." */
    if (in_fifo_.size() < words_per_line_) return;
    ExecuteCpuLine(lines_done_);
    in_fifo_.clear();
    if (++lines_done_ >= p_.height) cpu_op_active_ = false;
}

uint16_t Sed1356BitBlt::DataRead() {
    /* Programming Notes §10.2 (p. 68): the FIFO "can be read from only when
       not empty. Failing to monitor the FIFO status can result in a BitBLT
       FIFO overflow or underflow" - underflow yields bus data, not a fault. */
    if (out_fifo_.empty()) return 0u;
    const uint16_t v = out_fifo_.front();
    out_fifo_.pop_front();
    if (out_fifo_.empty()) RenderReadFifo();
    return v;
}

/* Programming Notes word-count formulas: §10.2.1 (write), §10.2.2 (color
   expand). The 8-bpp phase is source-address bit 0. */
uint32_t Sed1356BitBlt::WordsPerLine() const {
    if (p_.op == kColorExpand || p_.op == kColorExpandTransp) {
        const uint32_t skip = 8u * (p_.src & 1u) + (7u - (p_.rop & 0x7u));
        return (skip + p_.width + 15u) >> 4;
    }
    if (p_.bpp16) return p_.width;
    return (p_.width + (p_.src & 1u) + 1u) >> 1;
}

/* AB[20:0] addressing: accesses alias within the populated buffer (TM
   X25B-A-001 §10 Fig 10-1) via owner_.VramWrap - never fault. */
uint16_t Sed1356BitBlt::ReadPxAt(uint32_t byte_addr) const {
    const uint8_t* m = owner_.vram_.data();
    const uint8_t  lo = m[owner_.VramWrap(byte_addr)];
    if (!p_.bpp16) return lo;
    return (uint16_t)(lo | m[owner_.VramWrap(byte_addr + 1u)] << 8);
}

void Sed1356BitBlt::WritePxAt(uint32_t byte_addr, uint16_t v) {
    uint8_t* m = owner_.vram_.data();
    m[owner_.VramWrap(byte_addr)] = (uint8_t)v;
    if (p_.bpp16) m[owner_.VramWrap(byte_addr + 1u)] = (uint8_t)(v >> 8);
}

/* 8x8 pattern addressing, Programming Notes Table 10-3: the source start
   address encodes pattern base + start line + start pixel. */
uint16_t Sed1356BitBlt::PatternPx(uint32_t x, uint32_t y) const {
    uint32_t base, line0, px0;
    if (p_.bpp16) {
        base  = p_.src & ~0x7Fu;
        line0 = (p_.src >> 4) & 0x7u;
        px0   = (p_.src >> 1) & 0x7u;
    } else {
        base  = p_.src & ~0x3Fu;
        line0 = (p_.src >> 3) & 0x7u;
        px0   = p_.src & 0x7u;
    }
    const uint32_t line = (line0 + y) & 0x7u;
    const uint32_t px   = (px0 + x) & 0x7u;
    return ReadPxAt(base + (line * 8u + px) * p_.px);
}

/* Table 10-1 (S = source or pattern, D = destination). */
uint16_t Sed1356BitBlt::Rop(uint8_t code, uint16_t s, uint16_t d) {
    switch (code & 0xFu) {
        case 0x0: return 0;
        case 0x1: return (uint16_t)~(s | d);
        case 0x2: return (uint16_t)(~s & d);
        case 0x3: return (uint16_t)~s;
        case 0x4: return (uint16_t)(s & ~d);
        case 0x5: return (uint16_t)~d;
        case 0x6: return (uint16_t)(s ^ d);
        case 0x7: return (uint16_t)~(s & d);
        case 0x8: return (uint16_t)(s & d);
        case 0x9: return (uint16_t)~(s ^ d);
        case 0xA: return d;
        case 0xB: return (uint16_t)(~s | d);
        case 0xC: return s;
        case 0xD: return (uint16_t)(s | ~d);
        case 0xE: return (uint16_t)(s | d);
        default:  return 0xFFFFu;
    }
}

void Sed1356BitBlt::ExpandLine(uint32_t line, const uint16_t* words,
                               uint32_t nwords, uint32_t skip,
                               bool transparent) {
    for (uint32_t x = 0; x < p_.width; ++x) {
        const uint32_t pos = skip + x;
        if ((pos >> 4) >= nwords) return;
        const uint32_t bit = MonoBitOfWord(words[pos >> 4], pos & 0xFu);
        if (!bit && transparent) continue;
        WritePxAt(p_.dst + line * p_.dst_stride + x * p_.px,
                  bit ? p_.fg : p_.bg);
    }
}

void Sed1356BitBlt::ExecuteCpuLine(uint32_t y) {
    const uint16_t* lw = in_fifo_.data();
    const uint16_t cmp_mask = p_.bpp16 ? 0xFFFFu : 0xFFu;

    if (p_.op == kColorExpand || p_.op == kColorExpandTransp) {
        const uint32_t skip = 8u * (p_.src & 1u) + (7u - (p_.rop & 0x7u));
        ExpandLine(y, lw, words_per_line_, skip, p_.op == kColorExpandTransp);
        return;
    }

    /* kWriteRop / kTransparentWrite: §10.2.1/§10.2.7. 8 bpp packs pixel i of
       a line at byte (phase + i) of that line's word run. */
    const uint32_t phase = p_.bpp16 ? 0u : (p_.src & 1u);
    for (uint32_t x = 0; x < p_.width; ++x) {
        uint16_t s;
        if (p_.bpp16) {
            s = lw[x];
        } else {
            const uint32_t b = phase + x;
            s = (uint8_t)(lw[b >> 1] >> ((b & 1u) * 8u));
        }
        const uint32_t at = p_.dst + y * p_.dst_stride + x * p_.px;
        if (p_.op == kTransparentWrite) {
            if ((s & cmp_mask) != (p_.bg & cmp_mask)) WritePxAt(at, s);
        } else {
            WritePxAt(at, Rop(p_.rop, s, ReadPxAt(at)));
        }
    }
}

/* Read BitBLT (§10.2.13). 8 bpp packs pixel i of a line at byte (phase + i),
   phase = REG[108h] bit 0; the unused filler byte reads back 0. */
void Sed1356BitBlt::RenderReadFifo() {
    if (read_line_ >= p_.height) return;
    const uint32_t base = p_.src + read_line_ * p_.src_stride;
    if (p_.bpp16) {
        for (uint32_t x = 0; x < p_.width; ++x)
            out_fifo_.push_back(ReadPxAt(base + x * 2u));
    } else {
        const uint32_t phase    = p_.dst & 1u;
        const uint32_t per_line = (p_.width + phase + 1u) >> 1;
        for (uint32_t w = 0; w < per_line; ++w) {
            uint16_t v = 0;
            for (uint32_t b = 0; b < 2u; ++b) {
                const uint32_t i = w * 2u + b;
                if (i >= phase && i - phase < p_.width)
                    v |= (uint16_t)(ReadPxAt(base + i - phase) << (b * 8u));
            }
            out_fifo_.push_back(v);
        }
    }
    ++read_line_;
}

void Sed1356BitBlt::ExecuteDisplayOp() {
    const uint16_t cmp_mask = p_.bpp16 ? 0xFFFFu : 0xFFu;

    switch (p_.op) {
        case kMovePosRop:
            for (uint32_t y = 0; y < p_.height; ++y)
                for (uint32_t x = 0; x < p_.width; ++x) {
                    const uint32_t sa = p_.src + y * p_.src_stride + x * p_.px;
                    const uint32_t da = p_.dst + y * p_.dst_stride + x * p_.px;
                    WritePxAt(da, Rop(p_.rop, ReadPxAt(sa), ReadPxAt(da)));
                }
            return;

        /* §10.2.6: src/dst name the LAST pixel; the blt walks backward. */
        case kMoveNegRop:
            for (uint32_t y = 0; y < p_.height; ++y)
                for (uint32_t x = 0; x < p_.width; ++x) {
                    const uint32_t sa = p_.src - y * p_.src_stride - x * p_.px;
                    const uint32_t da = p_.dst - y * p_.dst_stride - x * p_.px;
                    WritePxAt(da, Rop(p_.rop, ReadPxAt(sa), ReadPxAt(da)));
                }
            return;

        case kTransparentMovePos:
            for (uint32_t y = 0; y < p_.height; ++y)
                for (uint32_t x = 0; x < p_.width; ++x) {
                    const uint16_t s =
                        ReadPxAt(p_.src + y * p_.src_stride + x * p_.px);
                    if ((s & cmp_mask) == (p_.bg & cmp_mask)) continue;
                    WritePxAt(p_.dst + y * p_.dst_stride + x * p_.px, s);
                }
            return;

        case kPatternFillRop:
            for (uint32_t y = 0; y < p_.height; ++y)
                for (uint32_t x = 0; x < p_.width; ++x) {
                    const uint32_t da = p_.dst + y * p_.dst_stride + x * p_.px;
                    WritePxAt(da, Rop(p_.rop, PatternPx(x, y), ReadPxAt(da)));
                }
            return;

        case kPatternFillTransp:
            for (uint32_t y = 0; y < p_.height; ++y)
                for (uint32_t x = 0; x < p_.width; ++x) {
                    const uint16_t s = PatternPx(x, y);
                    if ((s & cmp_mask) == (p_.bg & cmp_mask)) continue;
                    WritePxAt(p_.dst + y * p_.dst_stride + x * p_.px, s);
                }
            return;

        case kMoveColorExpand:
        case kMoveColorExpandTr: {
            /* Mono source in display memory; each line restarts at the
               line base's word with the REG[102h] start bit (§10.2.11). */
            const uint32_t start_bit = 7u - (p_.rop & 0x7u);
            for (uint32_t y = 0; y < p_.height; ++y) {
                const uint32_t line_base = p_.src + y * p_.src_stride;
                const uint32_t skip = 8u * (line_base & 1u) + start_bit;
                const uint32_t nwords = (skip + p_.width + 15u) >> 4;
                const uint32_t wbase = owner_.VramWrap(line_base & ~1u);
                std::vector<uint16_t> words(nwords);
                const uint32_t tail = owner_.VramSize() - wbase;
                if (nwords * 2u <= tail) {
                    std::memcpy(words.data(), owner_.vram_.data() + wbase,
                                nwords * 2u);
                } else {        /* run wraps the populated buffer boundary */
                    std::memcpy(words.data(), owner_.vram_.data() + wbase,
                                tail);
                    std::memcpy((uint8_t*)words.data() + tail,
                                owner_.vram_.data(), nwords * 2u - tail);
                }
                ExpandLine(y, words.data(), nwords, skip,
                           p_.op == kMoveColorExpandTr);
            }
            return;
        }

        case kSolidFill:
            for (uint32_t y = 0; y < p_.height; ++y)
                for (uint32_t x = 0; x < p_.width; ++x)
                    WritePxAt(p_.dst + y * p_.dst_stride + x * p_.px, p_.fg);
            return;

        default:
            return;
    }
}

void Sed1356BitBlt::SaveState(StateWriter& w) const {
    w.Write(p_);
    w.Write<uint8_t>(cpu_op_active_ ? 1u : 0u);
    w.Write(words_per_line_);
    w.Write(lines_done_);
    w.Write(read_line_);
    w.Write<uint64_t>(in_fifo_.size());
    for (uint16_t v : in_fifo_) w.Write<uint16_t>(v);
    w.Write<uint64_t>(out_fifo_.size());
    for (uint16_t v : out_fifo_) w.Write<uint16_t>(v);
}

void Sed1356BitBlt::RestoreState(StateReader& r) {
    r.Read(p_);
    uint8_t active = 0; r.Read(active); cpu_op_active_ = (active != 0);
    r.Read(words_per_line_);
    r.Read(lines_done_);
    r.Read(read_line_);
    uint64_t n = 0;
    r.Read(n); in_fifo_.clear();
    for (uint64_t i = 0; i < n; ++i) { uint16_t v = 0; r.Read(v); in_fifo_.push_back(v); }
    r.Read(n); out_fifo_.clear();
    for (uint64_t i = 0; i < n; ++i) { uint16_t v = 0; r.Read(v); out_fifo_.push_back(v); }
}
