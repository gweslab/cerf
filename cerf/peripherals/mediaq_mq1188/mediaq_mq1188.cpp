#include "mediaq_mq1188.h"

#include "../../boards/board_context.h"
#include "../../boards/falcon_pc3xx/falcon_4220_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_window.h"
#include "../peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstring>

bool MediaQMq1188::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Falcon4220;
}

void MediaQMq1188::OnReady() {
    sram_.assign(kApertureSize, 0u);
    reg_[kDc01R / 4u] = 0xF0000000u;   /* DC01R reset value (Table 4-2). */
    emu_.Get<PeripheralDispatcher>().Register(this);
}

bool MediaQMq1188::IsEnabled() const {
    /* GC08R/GC09R reset to 0, which the (n-1) geometry encoding reads back as a
       1-pixel dimension; require >1 so the enable edge fires on the programmed
       mode, not the transient state before the mode-set writes geometry. */
    return (Reg(kDc05R) & 0x1u) != 0u && GetGuestW() > 1u &&
           GetGuestH() > 1u && Stride() != 0u;
}

uint32_t MediaQMq1188::Bpp() const {
    switch ((Reg(kGc00R) >> 4u) & 0xFu) {  /* GC00R[7:4] color depth (Reg 4-31). */
        case 0x0u: return 1u;
        case 0x1u: return 2u;
        case 0x2u: return 4u;
        case 0x3u: return 8u;
        case 0x4u:
        case 0xCu: return 16u;
        default:   return 0u;
    }
}

uint32_t MediaQMq1188::GetGuestW()      const { return ((Reg(kGc08R) >> 16u) & 0xFFFFu) + 1u; }
uint32_t MediaQMq1188::GetGuestH()      const { return ((Reg(kGc09R) >> 16u) & 0xFFFFu) + 1u; }
uint32_t MediaQMq1188::FbWindowOffset() const { return Reg(kGc0CR) & 0x3FFFFu; }
uint32_t MediaQMq1188::Stride()         const { return Reg(kGc0ER) & 0x3FFFFu; }

uint32_t MediaQMq1188::PaletteEntry(uint32_t index) const {
    return Reg(kPaletteBase + (index & 0xFFu) * 4u);
}

void MediaQMq1188::PublishScreenSizeOnEnableEdge() {
    const bool enabled = IsEnabled();
    if (!enabled) { enable_published_ = false; return; }

    const uint32_t w = GetGuestW(), h = GetGuestH();
    if (enable_published_ && w == published_w_ && h == published_h_) return;

    enable_published_ = true;
    published_w_ = w;
    published_h_ = h;
    LOG(Lcd, "MediaQMq1188: display enabled %ux%u %ubpp stride=%u fb_off=0x%X\n",
        w, h, Bpp(), Stride(), FbWindowOffset());
    emu_.Get<HostWindow>().OnLcdEnabled();
}

uint32_t MediaQMq1188::RegRead(uint32_t addr) {
    const uint32_t roff = (addr - MmioBase()) - kRegBase;
    if (roff == kCc01R) { ge_.FlushPending(); return ge_.StatusReady(); }
    if (roff >= kGeCmdLo && roff < kGeCmdHi) return ge_.ReadReg((roff - kGeCmdLo) / 4u);
    if (IsUsbHost(roff)) {
        const uint32_t uoff = roff - kUsbLo;
        if (uoff == kHcRevision)      return 0x10u;  /* OHCI 1.0a. */
        if (uoff == kHcCommandStatus) return Reg(roff) & ~kHcrResetBit;
    }
    return Reg(roff);
}

void MediaQMq1188::RegWrite(uint32_t addr, uint32_t value) {
    const uint32_t roff = (addr - MmioBase()) - kRegBase;
    /* GE registers are reached only via the queued alias (0x1400). The 0x200
       block is the GE direct block on the MQ-1132 but the SD/MMC controller on
       the MQ-1188 (mq1188sdmmc.dll maps PA 0x08040200, writes DMA descriptors at
       0x22C) - routing it to the GE corrupts GE0BR. SD/MMC not yet modelled. */
    if (roff >= kGeCmdLo && roff < kGeCmdHi) { ge_.WriteReg((roff - kGeCmdLo) / 4u, value); return; }
    if (roff >= kSrcFifoLo && roff < kSrcFifoHi) { ge_.PushSourceFifo(value); return; }
    reg_[roff / 4u] = value;
    PublishScreenSizeOnEnableEdge();
}

uint8_t MediaQMq1188::ReadByte(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (InRegWindow(off)) {
        const uint32_t word = RegRead(addr & ~0x3u);
        return static_cast<uint8_t>(word >> ((off & 0x3u) * 8u));
    }
    return sram_[off];
}

uint16_t MediaQMq1188::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (InRegWindow(off)) {
        const uint32_t word = RegRead(addr & ~0x3u);
        return static_cast<uint16_t>(word >> ((off & 0x2u) * 8u));
    }
    return cerf::le::U16(&sram_[off]);
}

uint32_t MediaQMq1188::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (InRegWindow(off)) return RegRead(addr);
    return cerf::le::U32(&sram_[off]);
}

void MediaQMq1188::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - MmioBase();
    if (InRegWindow(off)) {
        const uint32_t shift = (off & 0x3u) * 8u;
        const uint32_t word  = RegRead(addr & ~0x3u);
        RegWrite(addr & ~0x3u,
                 (word & ~(0xFFu << shift)) | (static_cast<uint32_t>(value) << shift));
        return;
    }
    sram_[off] = value;
}

void MediaQMq1188::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
    if (InRegWindow(off)) {
        const uint32_t shift = (off & 0x2u) * 8u;
        const uint32_t word  = RegRead(addr & ~0x3u);
        RegWrite(addr & ~0x3u,
                 (word & ~(0xFFFFu << shift)) | (static_cast<uint32_t>(value) << shift));
        return;
    }
    cerf::le::Put16(&sram_[off], value);
}

void MediaQMq1188::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (InRegWindow(off)) { RegWrite(addr, value); return; }
    cerf::le::Put32(&sram_[off], value);
}

void MediaQMq1188::SaveState(StateWriter& w) {
    w.WriteBytes("sram", sram_.data(), sram_.size());
    w.WriteBytes("reg", reg_, sizeof(reg_));
    w.Write<uint8_t>(enable_published_ ? 1u : 0u);
    w.Write(published_w_);
    w.Write(published_h_);
    ge_.SaveState(w);
}

void MediaQMq1188::RestoreState(StateReader& r) {
    r.ReadBytes("sram", sram_.data(), sram_.size());
    r.ReadBytes("reg", reg_, sizeof(reg_));
    uint8_t en = 0; r.Read(en); enable_published_ = (en != 0);
    r.Read(published_w_);
    r.Read(published_h_);
    ge_.RestoreState(r);
}

REGISTER_SERVICE(MediaQMq1188);
