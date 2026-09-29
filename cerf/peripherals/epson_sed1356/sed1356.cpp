#include "sed1356.h"

#include "sed1356_config.h"
#include "sed1356_panel_power.h"
#include "sed1356_power_sequence.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../../core/fatal.h"

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
    bus_clock_hz_ = cfg.BusClockHz();
    power_seq_    = &emu_.Get<Sed1356PowerSequence>();
    panel_        = &emu_.Get<Sed1356PanelPower>();
    AttachScanClock();
    cfg.RegisterBusClockListener([this] { OnBusClockChange(); });
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

/* S1D13806 X28B-A-001-13 Table 8-35 p.147, SED1356 X25B-A-001-12 Table 8-36 p.172:
   REG[1FCh] bit 0 enables the LCD; Table 19-1 (p.200 / p.222): power save disables it. */
bool Sed1356::LcdPipelineRunning() const {
    return (Reg(0x1FC) & 0x1u) != 0u && (Reg(0x1F0) & 0x1u) == 0u;
}

/* SED1356 Table 8-36 p.172 (S1D13806 Table 8-35 p.147): modes 010-111 drive the CRT or TV;
   Table 19-1 (p.222 / p.200): power save disables them. */
bool Sed1356::CrtTvPipelineRunning() const {
    return (Reg(0x1FC) & 0x6u) != 0u && (Reg(0x1F0) & 0x1u) == 0u;
}

/* REG[030h] bit 1 = dual panel (S1D13806 p.108, SED1356 p.135); §18.1.1 n. */
uint32_t Sed1356::LcdPanelDivisor() const {
    return (Reg(0x30) & 0x2u) ? 2u : 1u;
}

/* §18.1.1 (S1D13806 p.186, SED1356 p.212): LHDP + LHNDP in Ts, LHNDP =
   (REG[034h] bits 4-0 + 1) x 8. */
uint64_t Sed1356::LcdLineTicks() const {
    return LcdGuestW() + ((Reg(0x34) & 0x1Fu) + 1u) * 8u;
}

/* REG[014h] (S1D13806 p.102 and X28B-R-001-03 p.3, SED1356 p.129): bits 1-0 source,
   01 = BUSCLK; bits 5-4 divide = value + 1. */
GuestCycleClock::Rate Sed1356::LcdPixelRate() const {
    const uint32_t pclk = Reg(0x14);
    if ((pclk & 0x3u) != 0x1u) {
        emu_.Get<Fatal>().Die("Sed1356: LCD PCLK source %u (REG[014h]=0x%02X) is not modelled",
                              pclk & 0x3u, pclk);
    }
    if (bus_clock_hz_ == 0u) {
        emu_.Get<Fatal>().Die("Sed1356: LCD pixel clock taken from a stopped BUSCLK is not "
                              "modelled");
    }
    return {bus_clock_hz_, ((pclk >> 4) & 0x3u) + 1u};
}

/* §18.1.1: line x (LVDP / n + LVNDP). */
RasterScanPeripheral::ScanShape Sed1356::ScanShapeLocked() const {
    const uint32_t n = LcdPanelDivisor();
    if (LcdGuestH() % n != 0u) {
        emu_.Get<Fatal>().Die("Sed1356: dual-panel LCD with an odd display height %u",
                              LcdGuestH());
    }
    ScanShape s;
    s.tick          = LcdPixelRate();
    s.frame.ticks   = LcdFrameTicks();
    s.frame.edges   = 1u;
    s.frame.edge[0] = s.frame.ticks;
    return s;
}

uint64_t Sed1356::LcdFrameTicks() const {
    return LcdLineTicks() * (LcdGuestH() / LcdPanelDivisor() + (Reg(0x3A) & 0x3Fu) + 1u);
}

/* REG[03Ah] bit 7 (S1D13806 p.112, SED1356 p.139): 1 while the vertical non-display
   period occurs; S1D13806 Figure 6-22 p.72: VDP lines, then VNDP lines. */
uint8_t Sed1356::LcdVndStatusBit() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    if (!ScanLiveLocked()) return panel_->VndWhileScanStopped();
    const uint64_t tick = ScanTicksLocked(ScanNow());
    if (tick < lcd_on_tick_) return 0x00u;
    const uint64_t display = LcdLineTicks() * (LcdGuestH() / LcdPanelDivisor());
    return (tick - lcd_on_tick_) % LcdFrameTicks() >= display ? 0x80u : 0x00u;
}

uint8_t Sed1356::LcdFieldMask(uint32_t off) const {
    switch (off) {
        case 0x014: return 0x33u;
        case 0x030: return 0x02u;
        case 0x032: return 0x7Fu;
        case 0x034: return 0x1Fu;
        case 0x038: return 0xFFu;
        case 0x039: return 0x03u;
        case 0x03A: return 0x3Fu;
        case 0x1F0: return 0x01u;
        case 0x1FC: return 0x01u;
    }
    emu_.Get<Fatal>().Die("Sed1356: REG[%03Xh] is not an LCD timing or power field", off);
}

/* SED1356 REG[1FCh] p.172: 0 to 1 starts the power-on sequence, 1 to 0 the power-off
   sequence; Table 7-21 p.80 t2/t4 give maxima only. */
void Sed1356::TrackLcdScanLocked(uint32_t off, uint8_t old) {
    const uint64_t now     = ScanNow();
    const bool     running = LcdPipelineRunning();
    const bool     changed = ((old ^ reg_[off]) & LcdFieldMask(off)) != 0u;
    if (!ScanLiveLocked()) {
        if (!running) {
            if (changed) panel_->Disturb();
            return;
        }
        StartScanLocked(now);
        lcd_on_tick_ =
            off == 0x1FCu ? LcdLineTicks() * power_seq_->LcdPowerOnLines(Reg(0x1F0)) : 0u;
        panel_->PowerUp();
        return;
    }
    if (!running) {
        StopScanLocked();
        panel_->PowerDown(off == 0x1FCu, {LcdPixelRate(), LcdFrameTicks(), LcdLineTicks(),
                                          LcdPanelDivisor(), Reg(0x1F0)});
        return;
    }
    if (changed) {
        emu_.Get<Fatal>().Die("Sed1356: LCD timing REG[%03Xh] 0x%02X -> 0x%02X while the LCD "
                              "pipeline runs", off, old, reg_[off]);
    }
}

void Sed1356::OnBusClockChange() {
    const uint64_t hz = emu_.Get<Sed1356Config>().BusClockHz();
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        if (hz == bus_clock_hz_) return;
        if (hz == 0u && (ScanLiveLocked() || panel_->PowerDownInProgress())) {
            emu_.Get<Fatal>().Die("Sed1356: BUSCLK stopped while the LCD scan or the panel "
                                  "power-down sequence runs is not modelled");
        }
        bus_clock_hz_ = hz;
        if (panel_->Pending()) panel_->SetPixelRate(LcdPixelRate());
    }
    OnScanSourceClockChange();
}

void Sed1356::PublishOnLcdEnableEdge() {
    const bool on = LcdDisplayOn();
    const uint32_t w = on ? LcdGuestW() : 0u, h = on ? LcdGuestH() : 0u;
    if (!mode_latch_.Publish(emu_, on, w, h)) return;
    LOG(Lcd, "Sed1356: LCD enabled %ux%u %ubpp start=0x%X stride=%u\n",
        w, h, LcdBpp(), LcdStartByte(), LcdStrideBytes());
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
        case 0x03A: return (uint8_t)((reg_[off] & 0x3Fu) | LcdVndStatusBit());
        case 0x058:
            if (CrtTvPipelineRunning()) {
                emu_.Get<Fatal>().Die("Sed1356: REG[058h] CRT/TV VND status read with the CRT/TV "
                                      "pipeline running (REG[1FCh]=0x%02X) is not modelled",
                                      Reg(0x1FC));
            }
            return static_cast<uint8_t>(reg_[off] & 0x7Fu);
        case 0x100: return blt_.Status();
        case 0x1E4: return ReadLutData();
        case 0x1F1: return panel_->StatusBits(Reg(0x1FC), Reg(0x1F0), Reg(0x21));
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
            switch (off) {
                case 0x014: case 0x030: case 0x032: case 0x034: case 0x038:
                case 0x039: case 0x03A: case 0x1F0: case 0x1FC: {
                    std::lock_guard<std::mutex> lk(state_mtx_);
                    const uint8_t old = reg_[off];
                    reg_[off] = value;
                    TrackLcdScanLocked(off, old);
                    break;
                }
                default:
                    reg_[off] = value;
                    break;
            }
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
    std::lock_guard<std::mutex> lk(state_mtx_);
    w.WriteBytes("reg", reg_, sizeof(reg_));
    w.WriteBytes("vram", vram_.data(), vram_.size());
    w.WriteBytes("lcd_lut", lcd_lut_, sizeof(lcd_lut_));
    w.WriteBytes("crt_lut", crt_lut_, sizeof(crt_lut_));
    w.Write("lut_index", lut_index_);
    w.Write("lut_component", lut_component_);
    w.WriteBytes("lut_rgb_latch", lut_rgb_latch_, sizeof(lut_rgb_latch_));
    mode_latch_.SaveState(w);
    blt_.SaveState(w);
    SaveScanLocked(w);
    w.Write<uint64_t>("lcd_on_tick", lcd_on_tick_);
    panel_->SaveState(w);
}

void Sed1356::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    r.ReadBytes("reg", reg_, sizeof(reg_));
    r.ReadBytes("vram", vram_.data(), vram_.size());
    r.ReadBytes("lcd_lut", lcd_lut_, sizeof(lcd_lut_));
    r.ReadBytes("crt_lut", crt_lut_, sizeof(crt_lut_));
    r.Read("lut_index", lut_index_);
    r.Read("lut_component", lut_component_);
    r.ReadBytes("lut_rgb_latch", lut_rgb_latch_, sizeof(lut_rgb_latch_));
    mode_latch_.RestoreState(r);
    blt_.RestoreState(r);
    RestoreScanLocked(r);
    r.Read("lcd_on_tick", lcd_on_tick_);
    panel_->RestoreState(r);
}

void Sed1356::PostRestore() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    bus_clock_hz_ = emu_.Get<Sed1356Config>().BusClockHz();
    ResumeScanLocked(ScanNow());
    panel_->ResumeAfterRestore();
}

REGISTER_SERVICE(Sed1356);
