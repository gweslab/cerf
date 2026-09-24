#include "mediaq_mq200.h"

#include "../../boards/board_context.h"
#include "../../boards/simpad_sl4/simpad_sl4_id.h"
#include "../../boards/smartbook_g138/smartbook_g138_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_window.h"
#include "../peripheral_dispatcher.h"
#include "../../state/state_stream.h"

bool MediaQMq200::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd) return false;
    const std::string_view b = bd->GetBoardId();
    return b == BoardId::SimpadSl4 || b == BoardId::SmartbookG138;
}

void MediaQMq200::OnReady() {
    fb_.assign(kFbSize, 0u);
    reg_.assign(kRegSize / 4u, 0u);
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t MediaQMq200::RegRead(uint32_t roff) {
    if (roff == kRegId)       return kDeviceId;
    if (roff == kRegIdle)     return reg_[roff / 4u] & ~0x3u;   /* WSM idle: clear busy [1:0]. */
    if (roff == kRegGeStatus) { ge_.FlushPending(); return ge_.StatusReady(); }
    if (roff >= kGeBlockLo && roff < kGeBlockHi)
        return ge_.ReadReg((roff - kGeBlockLo) / 4u);
    return reg_[roff / 4u];
}

void MediaQMq200::RegWrite(uint32_t roff, uint32_t value) {
    if (roff >= kGeBlockLo && roff < kGeBlockHi) {
        ge_.WriteReg((roff - kGeBlockLo) / 4u, value);
        return;
    }
    if (roff == kSrcFifo) { ge_.PushSourceFifo(value); return; }
    reg_[roff / 4u] = value;
    PublishScreenSizeOnEnableEdge();
}

uint32_t MediaQMq200::PanelGcBase() const {
    const uint32_t fp = Reg(kFp00R);                    /* FP00R[1:0] (Table 5-51). */
    if ((fp & kFpEnable) == 0u) return 0u;              /* x0: flat panel off. */
    return (fp & kFpDriveCtrl2) ? kGc2Base : kGc1Base;  /* 01=GC1, 11=GC2. */
}

bool MediaQMq200::IsEnabled() const {
    const uint32_t gc = PanelGcBase();
    return gc != 0u && (Reg(gc + kGcCtrl) & kGc00ImgWinEnable) != 0u &&
           GetGuestW() > 1u && GetGuestH() > 1u && Stride() != 0u;
}

uint32_t MediaQMq200::Bpp() const {
    const uint32_t gc = PanelGcBase();
    if (gc == 0u) return 0u;
    switch ((Reg(gc + kGcCtrl) >> 4u) & 0xFu) {   /* control[7:4] color depth (Table 5-8). */
        case 0x0u: return 1u;
        case 0x1u: return 2u;
        case 0x2u: return 4u;
        case 0x3u: return 8u;
        case 0x4u:
        case 0xCu: return 16u;
        case 0x5u:
        case 0xDu: return 24u;
        case 0x6u:
        case 0x7u:
        case 0xEu:
        case 0xFu: return 32u;
        default:   return 0u;
    }
}

uint32_t MediaQMq200::GetGuestW() const {
    const uint32_t gc = PanelGcBase();
    return gc ? (((Reg(gc + kGcHWin) >> 16u) & 0xFFFu) + 1u) : 0u;
}
uint32_t MediaQMq200::GetGuestH() const {
    const uint32_t gc = PanelGcBase();
    return gc ? (((Reg(gc + kGcVWin) >> 16u) & 0xFFFu) + 1u) : 0u;
}
uint32_t MediaQMq200::FbWindowOffset() const {
    const uint32_t gc = PanelGcBase();
    return gc ? (Reg(gc + kGcStart) & 0x1FFFFFu) : 0u;
}
uint32_t MediaQMq200::Stride() const {
    const uint32_t gc = PanelGcBase();
    return gc ? (Reg(gc + kGcStride) & 0xFFFFu) : 0u;
}

uint32_t MediaQMq200::PaletteEntry(uint32_t index) const {
    return Reg(kPaletteBase + (index & 0xFFu) * 4u);
}

void MediaQMq200::PublishScreenSizeOnEnableEdge() {
    if (!IsEnabled()) { enable_published_ = false; return; }

    const uint32_t w = GetGuestW(), h = GetGuestH();
    if (enable_published_ && w == published_w_ && h == published_h_) return;

    enable_published_ = true;
    published_w_ = w;
    published_h_ = h;
    LOG(Lcd, "MediaQMq200: display enabled %ux%u %ubpp stride=%u fb_off=0x%X\n",
        w, h, Bpp(), Stride(), FbWindowOffset());
    emu_.Get<HostWindow>().OnLcdEnabled();
}

/* Window layout: [0, kFbSize) framebuffer SRAM; [kRegWinOff, +kRegSize) the
   register block; the gap between is unmapped (the driver maps only those two
   VirtualCopy regions) and faults loud. */
uint8_t MediaQMq200::ReadByte(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off < kFbSize) return fb_[off];
    if (off >= kRegWinOff && off < kRegWinOff + kRegSize) {
        const uint32_t roff = off - kRegWinOff;
        return static_cast<uint8_t>(RegRead(roff & ~0x3u) >> ((roff & 0x3u) * 8u));
    }
    HaltUnsupportedAccess("MQ200 ReadByte", addr, 0);
}

uint16_t MediaQMq200::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off < kFbSize) return cerf::le::U16(fb_.data(), off);
    if (off >= kRegWinOff && off < kRegWinOff + kRegSize) {
        const uint32_t roff = off - kRegWinOff;
        return static_cast<uint16_t>(RegRead(roff & ~0x3u) >> ((roff & 0x2u) * 8u));
    }
    HaltUnsupportedAccess("MQ200 ReadHalf", addr, 0);
}

uint32_t MediaQMq200::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off < kFbSize) return cerf::le::U32(fb_.data(), off);
    if (off >= kRegWinOff && off < kRegWinOff + kRegSize) return RegRead(off - kRegWinOff);
    HaltUnsupportedAccess("MQ200 ReadWord", addr, 0);
}

void MediaQMq200::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - MmioBase();
    if (off < kFbSize) { fb_[off] = value; return; }
    if (off >= kRegWinOff && off < kRegWinOff + kRegSize) {
        const uint32_t roff  = off - kRegWinOff;
        const uint32_t shift = (roff & 0x3u) * 8u;
        const uint32_t word  = RegRead(roff & ~0x3u);
        RegWrite(roff & ~0x3u,
                 (word & ~(0xFFu << shift)) | (static_cast<uint32_t>(value) << shift));
        return;
    }
    HaltUnsupportedAccess("MQ200 WriteByte", addr, value);
}

void MediaQMq200::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
    if (off < kFbSize) { cerf::le::Put16(fb_.data() + off, value); return; }
    if (off >= kRegWinOff && off < kRegWinOff + kRegSize) {
        const uint32_t roff  = off - kRegWinOff;
        const uint32_t shift = (roff & 0x2u) * 8u;
        const uint32_t word  = RegRead(roff & ~0x3u);
        RegWrite(roff & ~0x3u,
                 (word & ~(0xFFFFu << shift)) | (static_cast<uint32_t>(value) << shift));
        return;
    }
    HaltUnsupportedAccess("MQ200 WriteHalf", addr, value);
}

void MediaQMq200::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off < kFbSize) { cerf::le::Put32(fb_.data() + off, value); return; }
    if (off >= kRegWinOff && off < kRegWinOff + kRegSize) { RegWrite(off - kRegWinOff, value); return; }
    HaltUnsupportedAccess("MQ200 WriteWord", addr, value);
}

void MediaQMq200::SaveState(StateWriter& w) {
    w.WriteBytes("fb", fb_.data(), fb_.size());
    w.WriteBytes("reg", reg_.data(), reg_.size() * sizeof(uint32_t));
    w.Write<uint8_t>(enable_published_ ? 1u : 0u);
    w.Write(published_w_);
    w.Write(published_h_);
    ge_.SaveState(w);
}

void MediaQMq200::RestoreState(StateReader& r) {
    r.ReadBytes("fb", fb_.data(), fb_.size());
    r.ReadBytes("reg", reg_.data(), reg_.size() * sizeof(uint32_t));
    uint8_t en = 0; r.Read(en); enable_published_ = (en != 0);
    r.Read(published_w_);
    r.Read(published_h_);
    ge_.RestoreState(r);
}

REGISTER_SERVICE(MediaQMq200);
