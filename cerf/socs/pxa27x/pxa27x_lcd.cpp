#include "pxa27x_lcd.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/host_window.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"

namespace {
/* Intel PXA27x Developer's Manual 280000-001 Table 7-40. */
constexpr uint32_t kLccr0Oum    = 1u << 21;
constexpr uint32_t kLccr0Bsm0   = 1u << 20;
constexpr uint32_t kLccr0Qdm    = 1u << 11;
constexpr uint32_t kLccr0Dis    = 1u << 10;
constexpr uint32_t kLccr0Eofm0  = 1u << 6;
constexpr uint32_t kLccr0Ium    = 1u << 5;
constexpr uint32_t kLccr0Sofm0  = 1u << 4;
constexpr uint32_t kLccr0Ldm    = 1u << 3;
constexpr uint32_t kLccr0Enb    = 1u << 0;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-58. */
constexpr uint32_t kLcsr0Sint   = 1u << 10;
constexpr uint32_t kLcsr0Bs0    = 1u << 9;
constexpr uint32_t kLcsr0Eof0   = 1u << 8;
constexpr uint32_t kLcsr0Qd     = 1u << 7;
constexpr uint32_t kLcsr0Ou     = 1u << 6;
constexpr uint32_t kLcsr0Iu1    = 1u << 5;
constexpr uint32_t kLcsr0Iu0    = 1u << 4;
constexpr uint32_t kLcsr0Ber    = 1u << 2;
constexpr uint32_t kLcsr0Sof0   = 1u << 1;
constexpr uint32_t kLcsr0Ldd    = 1u << 0;
constexpr uint32_t kLcsr0BerChShift = 28u;
/* Intel PXA27x Developer's Manual 280000-001 Table 7-58: bits 12:0 are R/W
   status bits, 30:28 BER_CH are read-only, 31 and 27:13 are reserved. */
constexpr uint32_t kLcsr0StickyMask = 0x00001FFFu;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-55. */
constexpr uint32_t kFbrBra  = 1u << 0;
constexpr uint32_t kFbrBint = 1u << 1;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-63. */
constexpr uint32_t kLdcmdPal     = 1u << 26;
constexpr uint32_t kLdcmdSofint  = 1u << 22;
constexpr uint32_t kLdcmdEofint  = 1u << 21;
constexpr uint32_t kLdcmdLenMask = 0x001FFFFCu;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-41 bits 9:0 PPL. */
constexpr uint32_t kLccr1PplMask = 0x3FFu;
/* Intel PXA27x Developer's Manual 280000-001 Table 7-42 bits 9:0 LPP. */
constexpr uint32_t kLccr2LppMask = 0x3FFu;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-43. */
constexpr uint32_t kLccr3Bpp3     = 1u << 29;
constexpr uint32_t kLccr3BppShift = 24u;
constexpr uint32_t kLccr3BppMask  = 0x7u << kLccr3BppShift;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-54: the descriptor address
   must be aligned on a 128-bit (16-byte) boundary; bits 3:0 are reserved. */
constexpr uint32_t kDescAddrMask = 0xFFFFFFF0u;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-61 bits 31:4 SRCADDR. */
constexpr uint32_t kSrcAddrMask = 0xFFFFFFF0u;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-62 bits 31:3 FRAME ID. */
constexpr uint32_t kFrameIdMask = 0xFFFFFFF8u;

/* Intel PXA27x Developer's Manual 280000-001 Table 25-2: IP[17] LCD controller
   interrupt. */
constexpr int kIntcLcdBit = 17;
}

bool Pxa27xLcd::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::PXA27x;
}

void Pxa27xLcd::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

bool Pxa27xLcd::IsKnown(uint32_t off) {
    if (off >= kDmaBase && off < kDmaEnd) return (off & 0x3u) == 0;
    switch (off) {
    case kLccr0: case kLccr1: case kLccr2: case kLccr3: case kLccr4: case kLccr5:
    case kFbr0: case kFbr0 + 0x4u: case kFbr0 + 0x8u: case kFbr0 + 0xCu: case kFbr4:
    case kLcsr1: case kLcsr0: case kLiidr: case kTrgbr: case kTcr:
    case kOvl1c1: case kOvl1c2: case kOvl2c1: case kOvl2c2: case kCcr:
    case kCmdcr: case kPrsr: case kFbr5: case kFbr6:
        return true;
    default:
        return false;
    }
}

bool Pxa27xLcd::IsEnabled() const {
    std::lock_guard<std::mutex> lk(state_mtx_);
    return (lccr_[0] & kLccr0Enb) != 0;
}

uint32_t Pxa27xLcd::GetGuestW() const {
    std::lock_guard<std::mutex> lk(state_mtx_);
    return (lccr_[1] & kLccr1PplMask) + 1u;
}

uint32_t Pxa27xLcd::GetGuestH() const {
    std::lock_guard<std::mutex> lk(state_mtx_);
    return (lccr_[2] & kLccr2LppMask) + 1u;
}

uint32_t Pxa27xLcd::GetBppCode() const {
    std::lock_guard<std::mutex> lk(state_mtx_);
    const uint32_t bpp3 = (lccr_[3] & kLccr3Bpp3) ? 0x8u : 0u;
    return bpp3 | ((lccr_[3] & kLccr3BppMask) >> kLccr3BppShift);
}

uint32_t Pxa27xLcd::GetChannelSrcPa(uint32_t channel) const {
    if (channel >= kChannels) return 0;
    std::lock_guard<std::mutex> lk(state_mtx_);
    return fsadr_[channel] & kSrcAddrMask;
}

uint32_t Pxa27xLcd::GetChannelLength(uint32_t channel) const {
    if (channel >= kChannels) return 0;
    std::lock_guard<std::mutex> lk(state_mtx_);
    return ldcmd_[channel] & kLdcmdLenMask;
}

bool Pxa27xLcd::ChannelIsPalette(uint32_t channel) const {
    if (channel >= kChannels) return false;
    std::lock_guard<std::mutex> lk(state_mtx_);
    return (ldcmd_[channel] & kLdcmdPal) != 0;
}

uint32_t Pxa27xLcd::UnmaskedStatusLocked() const {
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-40: LDM bit 3 masks
       LDD, SOFM0 bit 4 masks SOF0, IUM bit 5 masks LCSR0[IU0, IU1], EOFM0
       bit 6 masks EOF0, QDM bit 11 masks QD, BSM0 bit 20 masks BS0, OUM bit 21
       masks OU. Table 7-58 bit 2 BER names no LCCR0 mask. */
    uint32_t u = lcsr0_ & kLcsr0Ber;
    if (!(lccr_[0] & kLccr0Ldm))   u |= lcsr0_ & kLcsr0Ldd;
    if (!(lccr_[0] & kLccr0Sofm0)) u |= lcsr0_ & kLcsr0Sof0;
    if (!(lccr_[0] & kLccr0Ium))   u |= lcsr0_ & (kLcsr0Iu0 | kLcsr0Iu1);
    if (!(lccr_[0] & kLccr0Eofm0)) u |= lcsr0_ & kLcsr0Eof0;
    if (!(lccr_[0] & kLccr0Qdm))   u |= lcsr0_ & kLcsr0Qd;
    if (!(lccr_[0] & kLccr0Bsm0))  u |= lcsr0_ & kLcsr0Bs0;
    if (!(lccr_[0] & kLccr0Oum))   u |= lcsr0_ & kLcsr0Ou;
    return u;
}

bool Pxa27xLcd::IrqPendingLocked() const {
    return UnmaskedStatusLocked() != 0;
}

void Pxa27xLcd::PublishIrq(bool pending) {
    auto& intc = emu_.Get<IrqController>();
    if (pending) intc.AssertIrq(kIntcLcdBit);
    else         intc.DeAssertIrq(kIntcLcdBit);
}

void Pxa27xLcd::LatchInterruptIdLocked(uint32_t unmasked_before, uint32_t frame_id) {
    if ((UnmaskedStatusLocked() & ~unmasked_before) == 0) return;
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-58 bit 10 SINT: set
       when an unmasked interrupt occurs and there is a pending interrupt; the
       frame ID of the first interrupt is saved in the interrupt Frame ID
       register. */
    if (unmasked_before) lcsr0_ |= kLcsr0Sint;
    else                 liidr_ = frame_id;
}

void Pxa27xLcd::LoadChannelDescriptorLocked(uint32_t channel) {
    /* Intel PXA27x Developer's Manual 280000-001 Section 7.5.1.2.1: the FDADRx
       register is only bypassed when the frame branch register (FBRx) branch
       (BRA) bit is set. Table 7-55 bit 0 BRA: automatically cleared after
       loading the new Descriptor. */
    uint32_t desc = fdadr_[channel] & kDescAddrMask;
    bool branch_int = false;
    if (fbr_[channel] & kFbrBra) {
        desc = fbr_[channel] & kSrcAddrMask;
        branch_int = (fbr_[channel] & kFbrBint) != 0;
        fbr_[channel] &= ~kFbrBra;
    }
    if (desc == 0) return;

    const uint32_t before = UnmaskedStatusLocked();
    auto& mem = emu_.Get<EmulatedMemory>();

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-58 bit 2 BER: a bus
       error is signaled when the DMA controller attempts to access a reserved
       or nonexistent memory space; BER_CH bits 30:28 specify the channel. */
    if (!mem.TryTranslate(desc)) {
        lcsr0_ |= kLcsr0Ber | (channel << kLcsr0BerChShift);
        LatchInterruptIdLocked(before, fidr_[channel]);
        return;
    }

    /* Intel PXA27x Developer's Manual 280000-001 Section 7.5.1.2.1: Word[0]
       contains the value for FDADRx, Word[1] for FSADRx, Word[2] for FIDRx and
       Word[3] for LDCMDx. */
    fdadr_[channel] = mem.ReadWord(desc + 0x0u) & kDescAddrMask;
    fsadr_[channel] = mem.ReadWord(desc + 0x4u) & kSrcAddrMask;
    fidr_ [channel] = mem.ReadWord(desc + 0x8u) & kFrameIdMask;
    ldcmd_[channel] = mem.ReadWord(desc + 0xCu);

    if (channel != 0) return;

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-58 bit 1 SOF0: SOFINT
       is bit 22 of the fourth word of the channel 0 DMA descriptor. Bit 9 BS0:
       set after the DMA controller has branched and loaded the descriptor from
       FBR0[SRCADDR], and FBR0[BINT] is set. */
    if (ldcmd_[channel] & kLdcmdSofint) lcsr0_ |= kLcsr0Sof0;
    if (branch_int)                     lcsr0_ |= kLcsr0Bs0;
    LatchInterruptIdLocked(before, fidr_[channel]);
}

void Pxa27xLcd::AdvanceFrame() {
    bool pending;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        if (!(lccr_[0] & kLccr0Enb)) return;

        /* Intel PXA27x Developer's Manual 280000-001 Table 7-58 bit 8 EOF0: set
           when the DMA finished fetching a frame and the channel 0 Descriptor
           has EOFINT set (bit 21 of the fourth word of the DMA descriptor). */
        const uint32_t before = UnmaskedStatusLocked();
        if (ldcmd_[0] & kLdcmdEofint) lcsr0_ |= kLcsr0Eof0;
        LatchInterruptIdLocked(before, fidr_[0]);

        for (uint32_t ch = 0; ch < kChannels; ++ch) LoadChannelDescriptorLocked(ch);
        pending = IrqPendingLocked();
    }
    PublishIrq(pending);
}

uint32_t Pxa27xLcd::ReadRegLocked(uint32_t off) {
    if (off >= kDmaBase && off < kDmaEnd) {
        const uint32_t ch = (off - kDmaBase) / 0x10u;
        switch ((off - kDmaBase) & 0xCu) {
        case 0x0u: return fdadr_[ch];
        case 0x4u: return fsadr_[ch];
        case 0x8u: return fidr_ [ch];
        default:   return ldcmd_[ch];
        }
    }
    switch (off) {
    case kLccr0: case kLccr1: case kLccr2:
    case kLccr3: case kLccr4: case kLccr5: return lccr_[off / 4u];
    case kFbr0:        return fbr_[0];
    case kFbr0 + 0x4u: return fbr_[1];
    case kFbr0 + 0x8u: return fbr_[2];
    case kFbr0 + 0xCu: return fbr_[3];
    case kFbr4:        return fbr_[4];
    case kFbr5:        return fbr_[5];
    case kFbr6:        return fbr_[6];
    case kLcsr0:  return lcsr0_;
    case kLcsr1:  return lcsr1_;
    case kLiidr:  return liidr_;
    case kTrgbr:  return trgbr_;
    case kTcr:    return tcr_;
    case kOvl1c1: return ovl1c1_;
    case kOvl1c2: return ovl1c2_;
    case kOvl2c1: return ovl2c1_;
    case kOvl2c2: return ovl2c2_;
    case kCcr:    return ccr_;
    case kCmdcr:  return cmdcr_;
    case kPrsr:   return prsr_;
    default:      return 0;
    }
}

void Pxa27xLcd::WriteLccr0Locked(uint32_t value) {
    const bool was_enabled = (lccr_[0] & kLccr0Enb) != 0;
    lccr_[0] = value;

    /* Intel PXA27x Developer's Manual 280000-001 Section 7.5.1.2.1: the FDADRx
       register must be written with the location of the first descriptor before
       enabling the LCD controller; once enabled, the first descriptor is read
       and all four registers are written by the DMA controller. */
    if (!was_enabled) {
        if (value & kLccr0Enb)
            for (uint32_t ch = 0; ch < kChannels; ++ch) LoadChannelDescriptorLocked(ch);
        return;
    }

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-40 bit 10 DIS: the
       controller finishes the current frame, LCSR0[LDD] is set and hardware
       clears ENB. DIS itself reads 1 - "has been disabled, or is in the process
       of disabling". */
    if (value & kLccr0Dis) {
        lccr_[0] &= ~kLccr0Enb;
        lcsr0_   |= kLcsr0Ldd;
        return;
    }

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-58 bit 7 QD: set when
       ENB is cleared and the DMA finishes its current data burst. Table 7-40
       bit 3 LDM: clearing ENB forces a "quick reset", and LDD is not set. */
    if (!(value & kLccr0Enb)) lcsr0_ |= kLcsr0Qd;
}

void Pxa27xLcd::WriteRegLocked(uint32_t off, uint32_t value) {
    if (off >= kDmaBase && off < kDmaEnd) {
        const uint32_t ch = (off - kDmaBase) / 0x10u;
        /* Intel PXA27x Developer's Manual 280000-001 Section 7.5.1.2.1: the
           FSADRx, FIDRx and LDCMDx registers can be loaded only indirectly
           from DMA frame descriptors. */
        if (((off - kDmaBase) & 0xCu) == 0x0u) fdadr_[ch] = value & kDescAddrMask;
        return;
    }
    switch (off) {
    case kLccr0: WriteLccr0Locked(value); return;
    case kLccr1: case kLccr2:
    case kLccr3: case kLccr4: case kLccr5: lccr_[off / 4u] = value; return;
    case kFbr0:        fbr_[0] = value; return;
    case kFbr0 + 0x4u: fbr_[1] = value; return;
    case kFbr0 + 0x8u: fbr_[2] = value; return;
    case kFbr0 + 0xCu: fbr_[3] = value; return;
    case kFbr4:        fbr_[4] = value; return;
    case kFbr5:        fbr_[5] = value; return;
    case kFbr6:        fbr_[6] = value; return;
    /* Intel PXA27x Developer's Manual 280000-001 Section 7.5.20: writing a one
       to a sticky status bit clears it; writing a zero has no effect. Read-only
       flags are set and cleared by hardware; writes have no effect. */
    case kLcsr0: lcsr0_ &= ~(value & kLcsr0StickyMask); return;
    /* Intel PXA27x Developer's Manual 280000-001 Section 7.5.21: LCSR1 status
       bits are sticky and cleared by writing a one. */
    case kLcsr1: lcsr1_ &= ~value; return;
    case kTrgbr:  trgbr_  = value; return;
    case kTcr:    tcr_    = value; return;
    case kOvl1c1: ovl1c1_ = value; return;
    case kOvl1c2: ovl1c2_ = value; return;
    case kOvl2c1: ovl2c1_ = value; return;
    case kOvl2c2: ovl2c2_ = value; return;
    case kCcr:    ccr_    = value; return;
    case kCmdcr:  cmdcr_  = value; return;
    case kPrsr:   prsr_   = value; return;
    default:      return;
    }
}

uint32_t Pxa27xLcd::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    std::lock_guard<std::mutex> lk(state_mtx_);
    return ReadRegLocked(off);
}

void Pxa27xLcd::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    bool pending;
    bool enabled_edge;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        const bool was_enabled = (lccr_[0] & kLccr0Enb) != 0;
        WriteRegLocked(off, value);
        enabled_edge = !was_enabled && (lccr_[0] & kLccr0Enb) != 0;
        pending = IrqPendingLocked();
    }
    PublishIrq(pending);
    /* Intel PXA27x Developer's Manual 280000-001 Section 7.5.2 (page 7-55):
       "in the control registers must be programmed before setting
       LCCR0[ENB]". */
    if (enabled_edge) emu_.Get<HostWindow>().OnLcdEnabled();
}

void Pxa27xLcd::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    for (uint32_t i = 0; i < 6u; ++i) w.Write(lccr_[i]);
    w.Write(lcsr0_);
    w.Write(lcsr1_);
    w.Write(liidr_);
    w.Write(trgbr_);
    w.Write(tcr_);
    w.Write(cmdcr_);
    w.Write(prsr_);
    w.Write(ovl1c1_);
    w.Write(ovl1c2_);
    w.Write(ovl2c1_);
    w.Write(ovl2c2_);
    w.Write(ccr_);
    for (uint32_t i = 0; i < kChannels; ++i) {
        w.Write(fdadr_[i]);
        w.Write(fsadr_[i]);
        w.Write(fidr_ [i]);
        w.Write(ldcmd_[i]);
        w.Write(fbr_  [i]);
    }
}

void Pxa27xLcd::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    for (uint32_t i = 0; i < 6u; ++i) r.Read(lccr_[i]);
    r.Read(lcsr0_);
    r.Read(lcsr1_);
    r.Read(liidr_);
    r.Read(trgbr_);
    r.Read(tcr_);
    r.Read(cmdcr_);
    r.Read(prsr_);
    r.Read(ovl1c1_);
    r.Read(ovl1c2_);
    r.Read(ovl2c1_);
    r.Read(ovl2c2_);
    r.Read(ccr_);
    for (uint32_t i = 0; i < kChannels; ++i) {
        r.Read(fdadr_[i]);
        r.Read(fsadr_[i]);
        r.Read(fidr_ [i]);
        r.Read(ldcmd_[i]);
        r.Read(fbr_  [i]);
    }
}

void Pxa27xLcd::PostRestore() {
    bool pending;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        pending = IrqPendingLocked();
    }
    PublishIrq(pending);
}

REGISTER_SERVICE(Pxa27xLcd);
