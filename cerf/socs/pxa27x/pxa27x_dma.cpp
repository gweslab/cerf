#include "pxa27x_dma.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 5-22 (pages 5-51 through
   5-58) "DMA Controller Register Summary" address column. */
enum : uint32_t {
    kDcsrEnd    = 0x0080u,
    kDalgn      = 0x00A0u,
    kDpcsr      = 0x00A4u,
    kDrqsr0     = 0x00E0u,
    kDrqsr1     = 0x00E4u,
    kDrqsr2     = 0x00E8u,
    kDint       = 0x00F0u,
    kDrcmrLo    = 0x0100u,
    kDrcmrLoEnd = 0x0200u,
    kDrcmr23    = 0x015Cu,
    kChanFirst  = 0x0200u,
    kChanEnd    = 0x0400u,
    kDrcmrHi    = 0x1100u,
    kDrcmrHiEnd = 0x111Cu,
    kDrcmr74    = 0x1128u,
};

/* Table 5-22 (pages 5-53 through 5-58) "0x4000_0200 DDADR0", "0x4000_0204
   DSADR0", "0x4000_0208 DTADR0", "0x4000_020C DCMD0". */
enum : uint32_t {
    kChanStride = 0x10u,
    kOffDdadr = 0x0u, kOffDsadr = 0x4u, kOffDtadr = 0x8u,
};

}  /* namespace */

bool Pxa27xDma::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::PXA27x;
}

void Pxa27xDma::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t Pxa27xDma::ReadWord(uint32_t addr) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return ReadRegLocked(addr);
}

void Pxa27xDma::WriteWord(uint32_t addr, uint32_t value) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    WriteRegLocked(addr, value);
}

/* Table 5-18 (page 5-45) "3 R STOPINTR ... 0 = The channel is running / 1 = The
   channel is in uninitialized or stopped state". */
uint32_t Pxa27xDma::DcsrValue(uint32_t ch) const {
    const uint32_t v = dcsr_[ch];
    return (v & RUN) ? v : (v | STOPINTR);
}

/* Table 5-22 (page 5-53) "0x4000_015C reserved" between "0x4000_0158 DRCMR22"
   and "0x4000_0160 DRCMR24"; (page 5-58) "0x4000_111C-0x4000_1124 reserved"
   between "0x4000_1118 DRCMR70" and "0x4000_1128 DRCMR74". */
uint8_t* Pxa27xDma::DrcmrSlot(uint32_t off) {
    if (off >= kDrcmrLo && off < kDrcmrLoEnd && off != kDrcmr23)
        return &drcmr_lo_[(off - kDrcmrLo) / 4u];
    if (off >= kDrcmrHi && off < kDrcmrHiEnd)
        return &drcmr_hi_[(off - kDrcmrHi) / 4u];
    if (off == kDrcmr74) return &drcmr74_;
    return nullptr;
}

uint32_t Pxa27xDma::ReadRegLocked(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off & 0x3u) HaltUnsupportedAccess("ReadWord", addr, 0);
    if (off < kDcsrEnd) return DcsrValue(off / 4u);
    if (off >= kChanFirst && off < kChanEnd) {
        const uint32_t ch = (off - kChanFirst) / kChanStride;
        switch (off & 0xCu) {
        case kOffDdadr: return ddadr_[ch];
        case kOffDsadr: return dsadr_[ch];
        case kOffDtadr: return dtadr_[ch];
        default:        return dcmd_[ch];
        }
    }
    if (const uint8_t* slot = DrcmrSlot(off)) return *slot;
    switch (off) {
    /* Table 5-20 (page 5-49) "31:0 R/W DALGNx". */
    case kDalgn: return dalgn_;
    /* Table 5-21 (page 5-51) "31 R/W BrgSplit", "0 R BrgBusy Bridge Busy Status
       ... 0 = No pending PIO transactions across peripheral bus." */
    case kDpcsr: return dpcsr_;
    /* Table 5-17 (page 5-40) "4:0 R REQPEND Requests Pending Indicates the
       number of pending requests on DREQx." */
    case kDrqsr0: case kDrqsr1: case kDrqsr2: return 0u;
    case kDint: return Dint();
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa27xDma::WriteRegLocked(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off & 0x3u) HaltUnsupportedAccess("WriteWord", addr, value);
    if (off < kDcsrEnd) { WriteDcsrLocked(off / 4u, value); return; }
    if (off >= kChanFirst && off < kChanEnd) {
        const uint32_t ch = (off - kChanFirst) / kChanStride;
        switch (off & 0xCu) {
        case kOffDdadr: ddadr_[ch] = value & kDdadrMask; return;
        /* Table 5-13 (page 5-33) "31:2 R/W SRCADDR", "2 R/W SRCADDR or
           reserved", "1:0 R/W SRCADDR or reserved". */
        case kOffDsadr: dsadr_[ch] = value; return;
        /* Table 5-14 (page 5-34) "31:2 R/W TRGADDR", "2 R/W TRGADDR or
           reserved", "1:0 R/W TRGADDR or reserved". */
        case kOffDtadr: dtadr_[ch] = value; return;
        default:        dcmd_[ch]  = value & kDcmdMask; return;
        }
    }
    if (uint8_t* slot = DrcmrSlot(off)) {
        *slot = static_cast<uint8_t>(value & kDrcmrMask);
        return;
    }
    switch (off) {
    case kDalgn: dalgn_ = value; return;
    case kDpcsr: dpcsr_ = value & kDpcsrRw; return;
    /* Table 5-17 (page 5-40) "8 W CLR ... Writing 0b1 to this bit clears
       DRQSRx[REQPEND] and thereby clears all pending requests made by the
       external DMA request pin DREQx." */
    case kDrqsr0: case kDrqsr1: case kDrqsr2: return;
    /* Table 5-19 (page 5-48) "31:0 R CHLINTRx". */
    case kDint: return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa27xDma::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    w.WriteBytes(dcsr_,  sizeof(dcsr_));
    w.WriteBytes(ddadr_, sizeof(ddadr_));
    w.WriteBytes(dsadr_, sizeof(dsadr_));
    w.WriteBytes(dtadr_, sizeof(dtadr_));
    w.WriteBytes(dcmd_,  sizeof(dcmd_));
    w.WriteBytes(drcmr_lo_, sizeof(drcmr_lo_));
    w.WriteBytes(drcmr_hi_, sizeof(drcmr_hi_));
    w.Write(drcmr74_);
    w.Write(dalgn_);
    w.Write(dpcsr_);
}

void Pxa27xDma::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    r.ReadBytes(dcsr_,  sizeof(dcsr_));
    r.ReadBytes(ddadr_, sizeof(ddadr_));
    r.ReadBytes(dsadr_, sizeof(dsadr_));
    r.ReadBytes(dtadr_, sizeof(dtadr_));
    r.ReadBytes(dcmd_,  sizeof(dcmd_));
    r.ReadBytes(drcmr_lo_, sizeof(drcmr_lo_));
    r.ReadBytes(drcmr_hi_, sizeof(drcmr_hi_));
    r.Read(drcmr74_);
    r.Read(dalgn_);
    r.Read(dpcsr_);
    for (uint32_t ch = 0; ch < kNumChannels; ++ch) {
        audio_active_[ch] = false;
        audio_sink_[ch]   = nullptr;
    }
}

REGISTER_SERVICE(Pxa27xDma);
