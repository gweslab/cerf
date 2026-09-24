#include "sed1356.h"

#include "sed1356_config.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_window.h"
#include "../peripheral_dispatcher.h"
#include "../../state/state_stream.h"

bool Sed1356::ShouldRegister() {
    return emu_.TryGet<Sed1356Config>() != nullptr;
}

void Sed1356::OnReady() {
    auto& cfg = emu_.Get<Sed1356Config>();
    mmio_base_        = cfg.HostWindowBase();
    vram_size_        = cfg.DisplayBufferBytes();
    vram_mask_        = (vram_size_ & (vram_size_ - 1u)) ? 0u : (vram_size_ - 1u);
    product_rev_code_ = cfg.ProductRevCode();
    vram_.assign(vram_size_, 0u);
    /* §8.1 reset-lock, board-dependent (see Sed1356Config). */
    reg_[0x01] = cfg.RegMemSelectLockedAtReset() ? 0x80u : 0x00u;
    boot_time_ = std::chrono::steady_clock::now();
    emu_.Get<PeripheralDispatcher>().Register(this);
}

bool Sed1356::LcdDisplayOn() const {
    const uint32_t mode = Reg(0x1FC) & 0x7u;   /* Table 8-36. */
    return mode == 0x1u || mode == 0x3u;       /* LCD only / CRT and LCD. */
}

uint32_t Sed1356::LcdBpp() const {
    switch (Reg(0x40) & 0x7u) {                /* Table 8-20. */
        case 0x2u: return 4u;
        case 0x3u: return 8u;
        case 0x4u: return 15u;
        case 0x5u: return 16u;
        default:   return 0u;                  /* reserved encodings. */
    }
}

void Sed1356::LcdLutRgb(uint32_t index, uint8_t& r4, uint8_t& g4,
                        uint8_t& b4) const {
    r4 = lcd_lut_[index & 0xFFu][0];
    g4 = lcd_lut_[index & 0xFFu][1];
    b4 = lcd_lut_[index & 0xFFu][2];
}

uint32_t Sed1356::LcdInkCursorStartByte() const {
    const uint32_t n = Reg(0x71);              /* Table 14-1 encoding. */
    return n == 0 ? vram_size_ - 1024u : vram_size_ - n * 8192u;
}

void Sed1356::LcdInkColor(uint32_t which, uint8_t& r5, uint8_t& g6,
                          uint8_t& b5) const {
    const uint32_t base = which ? 0x7Au : 0x76u;  /* REG[076h..078h] / [07Ah..07Ch]. */
    b5 = Reg(base + 0) & 0x1Fu;
    g6 = Reg(base + 1) & 0x3Fu;
    r5 = Reg(base + 2) & 0x1Fu;
}

/* REG[03Ah] bit 7 (§8.3.6): 1 while the vertical non-display period is
   occurring. CERF has no pixel clock, so the bit is phased off a synthetic
   60 Hz host-clock frame; both states occur every frame, which is what
   guest VND poll loops require to terminate. */
uint8_t Sed1356::VndStatusBit() const {
    const uint32_t vdh = LcdGuestH();
    const uint32_t vnd = (Reg(0x3A) & 0x3Fu) + 1u;
    const auto since = std::chrono::steady_clock::now() - boot_time_;
    const uint64_t us = (uint64_t)std::chrono::duration_cast<
        std::chrono::microseconds>(since).count();
    const uint64_t frame_us = 16667u;          /* synthetic 60 Hz. */
    const uint64_t in_frame = us % frame_us;
    const uint64_t vnd_us   = frame_us * vnd / (vdh + vnd);
    return in_frame < vnd_us ? 0x80u : 0x00u;
}

void Sed1356::PublishOnLcdEnableEdge() {
    if (!LcdDisplayOn()) { enable_published_ = false; return; }
    const uint32_t w = LcdGuestW(), h = LcdGuestH();
    if (enable_published_ && w == published_w_ && h == published_h_) return;

    enable_published_ = true;
    published_w_ = w;
    published_h_ = h;
    LOG(Lcd, "Sed1356: LCD enabled %ux%u %ubpp start=0x%X stride=%u\n",
        w, h, LcdBpp(), LcdStartByte(), LcdStrideBytes());
    emu_.Get<HostWindow>().OnLcdEnabled();
}

namespace {

/* Documented register offsets, §8.3 (read in full from the technical
   manual; everything else in the 0x000..0x1FF window is unpopulated). */
bool IsDocumentedReg(uint32_t off) {
    switch (off) {
        case 0x000: case 0x001: case 0x004: case 0x005: case 0x008: case 0x009:
        case 0x00C: case 0x00D:
        case 0x010: case 0x014: case 0x018: case 0x01C: case 0x01E:
        case 0x020: case 0x021: case 0x02A: case 0x02B:
        case 0x030: case 0x031: case 0x032: case 0x034: case 0x035:
        case 0x036: case 0x038: case 0x039: case 0x03A: case 0x03B:
        case 0x03C:
        case 0x040: case 0x041: case 0x042: case 0x043: case 0x044:
        case 0x046: case 0x047: case 0x048: case 0x04A: case 0x04B:
        case 0x050: case 0x052: case 0x053: case 0x054: case 0x056:
        case 0x057: case 0x058: case 0x059: case 0x05A: case 0x05B:
        case 0x060: case 0x062: case 0x063: case 0x064: case 0x066:
        case 0x067: case 0x068: case 0x06A: case 0x06B:
        case 0x070: case 0x071: case 0x072: case 0x073: case 0x074:
        case 0x075: case 0x076: case 0x077: case 0x078: case 0x07A:
        case 0x07B: case 0x07C: case 0x07E:
        case 0x080: case 0x081: case 0x082: case 0x083: case 0x084:
        case 0x085: case 0x086: case 0x087: case 0x088: case 0x08A:
        case 0x08B: case 0x08C: case 0x08E:
        case 0x100: case 0x101: case 0x102: case 0x103: case 0x104:
        case 0x105: case 0x106: case 0x108: case 0x109: case 0x10A:
        case 0x10C: case 0x10D: case 0x110: case 0x111: case 0x112:
        case 0x113: case 0x114: case 0x115: case 0x118: case 0x119:
        case 0x1E0: case 0x1E2: case 0x1E4:
        case 0x1F0: case 0x1F1: case 0x1F4: case 0x1FC:
            return true;
        default:
            return false;
    }
}

}  /* namespace */

uint8_t Sed1356::RegRead(uint32_t off) {
    /* §8.1: while Register/Memory Select is set only 0x000/0x001 decode. */
    if ((reg_[0x01] & 0x80u) && off > 0x001u)
        HaltUnsupportedAccess("RegRead(locked)", MmioBase() + off, 0);

    switch (off) {
        case 0x000: return product_rev_code_;   /* per-board (Sed1356Config). */
        case 0x00C:                 /* MD[15:0] readback = board strap pins; */
        case 0x00D:                 /* Jornada strap values not grounded yet. */
            HaltUnsupportedAccess("RegRead(MD readback)", MmioBase() + off, 0);
        case 0x03A: return (uint8_t)((reg_[off] & 0x3Fu) | VndStatusBit());
        case 0x100: return blt_.Status();
        case 0x1E4: return ReadLutData();
        case 0x1F1: return (reg_[0x1F0] & 0x1u) ? 0x03u : 0x00u;  /* §8.3.14. */
        default:
            /* §8.2 / Table 8-1: the full 0x000..0x1FF window is decoded
               register space; reserved registers (REG[033h] etc.) read back
               their stored byte, 0 when never written. Guest drivers read
               them in contiguous bulk register saves. */
            return reg_[off];
    }
}

void Sed1356::RegWrite(uint32_t off, uint8_t value) {
    if ((reg_[0x01] & 0x80u) && off > 0x001u)
        HaltUnsupportedAccess("RegWrite(locked)", MmioBase() + off, value);

    switch (off) {
        case 0x000: return;                       /* RO revision code. */
        case 0x1E2:
            reg_[off] = value;                    /* §8.3.13: address write */
            lut_index_     = value;               /* points at the Red LUT. */
            lut_component_ = 0;
            return;
        case 0x1E4: WriteLutData(value); return;
        case 0x100:
            reg_[off] = value & 0x03u;            /* dest/src linear selects. */
            if (value & 0x80u) blt_.Start();      /* §10.1 write data path. */
            return;
        case 0x1F1: return;                       /* RO power-save status. */
        default:
            if (!IsDocumentedReg(off)) {
                /* Unpopulated pad byte. Guest drivers reach these through
                   multi-byte stores spanning a register group (e.g. the
                   32-bit dest-address store covering 0x108..0x10B); the
                   chip ignores them. */
                if (dropped_logged_.insert(off).second)
                    LOG(Periph, "[Sed1356] dropped write to unpopulated reg "
                        "0x%03X = 0x%02X\n", off, value);
                return;
            }
            reg_[off] = value;
            PublishOnLcdEnableEdge();
            return;
    }
}

/* §8.3.13: LUT data sits in bits 7:4; the pointer auto-increments per access
   R->G->B->next entry; an entry commits only after its Blue write. REG[1E0h]
   bits 1:0 pick which LUT(s) a read/write touches (Table 8-34). */
uint8_t Sed1356::ReadLutData() {
    const uint32_t mode = reg_[0x1E0] & 0x3u;
    const uint8_t (*lut)[3] = (mode == 0x2u) ? crt_lut_ : lcd_lut_;
    const uint8_t v = (uint8_t)(lut[lut_index_][lut_component_] << 4);
    StepLutPointer();
    return v;
}

void Sed1356::WriteLutData(uint8_t value) {
    const uint8_t comp = (uint8_t)(value >> 4);
    if (lut_component_ < 2) {
        lut_rgb_latch_[lut_component_] = comp;
    } else {
        const uint32_t mode = reg_[0x1E0] & 0x3u;
        const bool to_lcd = (mode == 0x0u || mode == 0x1u);
        const bool to_crt = (mode == 0x0u || mode == 0x2u);
        if (to_lcd) {
            lcd_lut_[lut_index_][0] = lut_rgb_latch_[0];
            lcd_lut_[lut_index_][1] = lut_rgb_latch_[1];
            lcd_lut_[lut_index_][2] = comp;
        }
        if (to_crt) {
            crt_lut_[lut_index_][0] = lut_rgb_latch_[0];
            crt_lut_[lut_index_][1] = lut_rgb_latch_[1];
            crt_lut_[lut_index_][2] = comp;
        }
    }
    StepLutPointer();
}

void Sed1356::StepLutPointer() {
    if (++lut_component_ == 3) {
        lut_component_ = 0;
        lut_index_++;                              /* wraps at 256 entries. */
    }
}

uint32_t Sed1356::VramLoad(uint32_t off, uint32_t width) const {
    const uint32_t r = VramWrap(off);
    if (r + width <= vram_size_) return static_cast<uint32_t>(cerf::le::UN(&vram_[r], width));
    uint32_t v = 0;
    for (uint32_t i = 0; i < width; ++i) v |= uint32_t(vram_[VramWrap(r + i)]) << (8u * i);
    return v;
}

void Sed1356::VramStore(uint32_t off, uint32_t value, uint32_t width) {
    const uint32_t r = VramWrap(off);
    if (r + width <= vram_size_) {
        cerf::le::PutN(&vram_[r], value, width);
        return;
    }
    for (uint32_t i = 0; i < width; ++i) vram_[VramWrap(r + i)] = uint8_t(value >> (8u * i));
}

uint8_t Sed1356::ReadByte(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off < kRegWindow) return RegRead(off);
    if (off >= kVramBase && off < kVramBase + kVramAperture)
        return vram_[VramWrap(off - kVramBase)];
    /* §8.3.18: byte access to the BitBLT data registers is not allowed. */
    HaltUnsupportedAccess("ReadByte", addr, 0);
}

uint16_t Sed1356::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off < kRegWindow)
        return (uint16_t)(RegRead(off) | (RegRead(off + 1) << 8));
    if (off >= kBltAperture && off < kBltApertureEnd) return blt_.DataRead();
    if (off >= kVramBase && off + 1 < kVramBase + kVramAperture) {
        return static_cast<uint16_t>(VramLoad(off - kVramBase, 2u));
    }
    HaltUnsupportedAccess("ReadHalf", addr, 0);
}

uint32_t Sed1356::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off < kRegWindow)
        return (uint32_t)RegRead(off)       | (uint32_t)RegRead(off + 1) << 8 |
               (uint32_t)RegRead(off + 2) << 16 | (uint32_t)RegRead(off + 3) << 24;
    if (off >= kBltAperture && off < kBltApertureEnd) {
        const uint32_t lo = blt_.DataRead();
        return lo | (uint32_t)blt_.DataRead() << 16;
    }
    if (off >= kVramBase && off + 3 < kVramBase + kVramAperture) {
        return VramLoad(off - kVramBase, 4u);
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sed1356::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - MmioBase();
    if (off < kRegWindow) { RegWrite(off, value); return; }
    if (off >= kVramBase && off < kVramBase + kVramAperture) {
        vram_[VramWrap(off - kVramBase)] = value;
        return;
    }
    HaltUnsupportedAccess("WriteByte", addr, value);
}

void Sed1356::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
    if (off < kRegWindow) {
        RegWrite(off,      (uint8_t)value);
        RegWrite(off + 1u, (uint8_t)(value >> 8));
        return;
    }
    if (off >= kBltAperture && off < kBltApertureEnd) {
        blt_.DataWrite(value);
        return;
    }
    if (off >= kVramBase && off + 1 < kVramBase + kVramAperture) {
        VramStore(off - kVramBase, value, 2u);
        return;
    }
    HaltUnsupportedAccess("WriteHalf", addr, value);
}

void Sed1356::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off < kRegWindow) {
        RegWrite(off,      (uint8_t)value);
        RegWrite(off + 1u, (uint8_t)(value >> 8));
        RegWrite(off + 2u, (uint8_t)(value >> 16));
        RegWrite(off + 3u, (uint8_t)(value >> 24));
        return;
    }
    if (off >= kBltAperture && off < kBltApertureEnd) {
        blt_.DataWrite((uint16_t)value);
        blt_.DataWrite((uint16_t)(value >> 16));
        return;
    }
    if (off >= kVramBase && off + 3 < kVramBase + kVramAperture) {
        VramStore(off - kVramBase, value, 4u);
        return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Sed1356::SaveState(StateWriter& w) {
    w.WriteBytes("reg", reg_, sizeof(reg_));
    w.WriteBytes("vram", vram_.data(), vram_.size());
    w.WriteBytes("lcd_lut", lcd_lut_, sizeof(lcd_lut_));
    w.WriteBytes("crt_lut", crt_lut_, sizeof(crt_lut_));
    w.Write("lut_index", lut_index_);
    w.Write("lut_component", lut_component_);
    w.WriteBytes("lut_rgb_latch", lut_rgb_latch_, sizeof(lut_rgb_latch_));
    w.Write<uint8_t>(enable_published_ ? 1u : 0u);
    w.Write(published_w_);
    w.Write(published_h_);
    blt_.SaveState(w);
}

void Sed1356::RestoreState(StateReader& r) {
    r.ReadBytes("reg", reg_, sizeof(reg_));
    r.ReadBytes("vram", vram_.data(), vram_.size());
    r.ReadBytes("lcd_lut", lcd_lut_, sizeof(lcd_lut_));
    r.ReadBytes("crt_lut", crt_lut_, sizeof(crt_lut_));
    r.Read("lut_index", lut_index_);
    r.Read("lut_component", lut_component_);
    r.ReadBytes("lut_rgb_latch", lut_rgb_latch_, sizeof(lut_rgb_latch_));
    uint8_t en = 0; r.Read(en); enable_published_ = (en != 0);
    r.Read(published_w_);
    r.Read(published_h_);
    blt_.RestoreState(r);
}

REGISTER_SERVICE(Sed1356);
