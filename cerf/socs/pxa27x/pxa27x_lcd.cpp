#include "pxa27x_lcd.h"

#include "../../boards/board_context.h"
#include "pxa270_id.h"
#include "pxa27x_clock_manager.h"
#include "pxa27x_lcd_dma.h"
#include "../../core/bit_field.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../host/host_window.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"

namespace {
/* Intel PXA27x Developer's Manual 280000-001 Table 7-40. */
constexpr uint32_t kLccr0Lcdt   = 1u << 22;
constexpr uint32_t kLccr0Oum    = 1u << 21;
constexpr uint32_t kLccr0Bsm0   = 1u << 20;
constexpr uint32_t kLccr0Qdm    = 1u << 11;
constexpr uint32_t kLccr0Dis    = 1u << 10;
constexpr uint32_t kLccr0Pas    = 1u << 7;
constexpr uint32_t kLccr0Eofm0  = 1u << 6;
constexpr uint32_t kLccr0Ium    = 1u << 5;
constexpr uint32_t kLccr0Sofm0  = 1u << 4;
constexpr uint32_t kLccr0Ldm    = 1u << 3;
constexpr uint32_t kLccr0Sds    = 1u << 2;
constexpr uint32_t kLccr0Enb    = 1u << 0;
constexpr uint32_t kLccr0Timing = kLccr0Lcdt | kLccr0Pas | kLccr0Sds;

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
/* Intel PXA27x Developer's Manual 280000-001 Table 7-58: bits 12:0 are R/W
   status bits, 30:28 BER_CH are read-only, 31 and 27:13 are reserved. */
constexpr uint32_t kLcsr0StickyMask = 0x00001FFFu;

constexpr uint32_t kLccr1PplMask = 0x3FFu;
constexpr uint32_t kLccr2LppMask = 0x3FFu;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-43. */
constexpr uint32_t kLccr3Bpp3     = 1u << 29;
constexpr uint32_t kLccr3Dpc      = 1u << 27;
constexpr uint32_t kLccr3BppShift = 24u;
constexpr uint32_t kLccr3BppMask  = 0x7u << kLccr3BppShift;
constexpr uint32_t kLccr3ApiMask  = 0xFu << 16;
constexpr uint32_t kLccr3PcdMask  = 0xFFu;
constexpr uint32_t kLccr3Timing   = kLccr3ApiMask | kLccr3PcdMask | kLccr3Dpc;

/* Intel PXA27x Developer's Manual 280000-001 Table 7-44. */
constexpr uint32_t kLccr4Pcddiv = 1u << 31;

constexpr uint32_t kOvl1c1O1en = 1u << 31;
constexpr uint32_t kOvl2c1O2en = 1u << 31;
constexpr uint32_t kCcrCen     = 1u << 31;

constexpr uint32_t kOvlC1Reset = 0x00200000u;
constexpr uint32_t kTrgbrReset = 0x00AA5500u;
constexpr uint32_t kTcrReset   = 0x0000754Fu;

/* Intel PXA27x Developer's Manual 280000-001 Table 25-2: IP[17] LCD controller
   interrupt. */
constexpr int kIntcLcdBit = 17;
}

bool Pxa27xLcd::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Pxa270;
}

void Pxa27xLcd::OnReady() {
    dma_ = &emu_.Get<Pxa27xLcdDma>();
    AttachScanClock();
    emu_.Get<Pxa27xClockManager>().RegisterLcdClockListener([this] {
        OnScanFunctionalClockChange(emu_.Get<Pxa27xClockManager>().LcdClockEnabled());
    });
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        {
            std::lock_guard<std::mutex> lk(state_mtx_);
            StopScanLocked();
            ResetRegistersLocked();
        }
        PublishIrq(false);
    });
    ResetRegistersLocked();
    emu_.Get<PeripheralDispatcher>().Register(this);
}

/* Intel PXA27x Developer's Manual 280000-001 Section 3.4.2: all units except
   the Table 3-2 registers start with their reset conditions; LIIDR (Table
   7-60) resets to an undefined value. */
void Pxa27xLcd::ResetRegistersLocked() {
    for (auto& v : lccr_) v = 0u;
    lcsr0_  = 0u;
    lcsr1_  = 0u;
    trgbr_  = kTrgbrReset;
    tcr_    = kTcrReset;
    cmdcr_  = 0u;
    prsr_   = 0u;
    ovl1c1_ = kOvlC1Reset;
    ovl1c2_ = 0u;
    ovl2c1_ = kOvlC1Reset;
    ovl2c2_ = 0u;
    ccr_    = 0u;
    dma_->Reset();
}

bool Pxa27xLcd::IsKnown(uint32_t off) {
    if (Pxa27xLcdDma::Decodes(off)) return true;
    switch (off) {
    case kLccr0: case kLccr1: case kLccr2: case kLccr3: case kLccr4: case kLccr5:
    case kLcsr1: case kLcsr0: case kLiidr: case kTrgbr: case kTcr:
    case kOvl1c1: case kOvl1c2: case kOvl2c1: case kOvl2c2: case kCcr:
    case kCmdcr: case kPrsr:
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
    return BppCodeLocked();
}

uint32_t Pxa27xLcd::BppCodeLocked() const {
    const uint32_t bpp3 = (lccr_[3] & kLccr3Bpp3) ? 0x8u : 0u;
    return bpp3 | ((lccr_[3] & kLccr3BppMask) >> kLccr3BppShift);
}

uint32_t Pxa27xLcd::GetChannelSrcPa(uint32_t channel) const {
    return dma_->SrcPa(channel);
}

uint32_t Pxa27xLcd::GetChannelLength(uint32_t channel) const {
    return dma_->Length(channel);
}

bool Pxa27xLcd::ChannelIsPalette(uint32_t channel) const {
    return dma_->IsPalette(channel);
}

uint32_t Pxa27xLcd::UnmaskedStatusLocked() const {
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

void Pxa27xLcd::ScanEdgesRan() {
    bool pending;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        pending = IrqPendingLocked();
    }
    PublishIrq(pending);
}

void Pxa27xLcd::LatchInterruptIdLocked(uint32_t unmasked_before, uint32_t frame_id) {
    if ((UnmaskedStatusLocked() & ~unmasked_before) == 0) return;
    if (unmasked_before) lcsr0_ |= kLcsr0Sint;
    else                 liidr_ = frame_id;
}

bool Pxa27xLcd::LoadChannel0DescriptorLocked() {
    const uint32_t before = UnmaskedStatusLocked();
    const Pxa27xLcdDma::Fetch f = dma_->FetchChannel0();
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-58 bit 2 BER with
       BER_CH 0; bit 1 SOF0 per the descriptor's SOFINT (Table 7-63 bit 22);
       bit 9 BS0 after a branch with FBR0[BINT] (Table 7-55). */
    if (!f.loaded) lcsr0_ |= kLcsr0Ber;
    if (f.sof)      lcsr0_ |= kLcsr0Sof0;
    if (f.branched) lcsr0_ |= kLcsr0Bs0;
    LatchInterruptIdLocked(before, f.frame_id);
    return f.loaded;
}

void Pxa27xLcd::RequireWholeFrameDescriptorLocked() const {
    dma_->RequireWholeFrame(BppCodeLocked(), (lccr_[1] & kLccr1PplMask) + 1u,
                            (lccr_[2] & kLccr2LppMask) + 1u);
}

void Pxa27xLcd::LoadFrameDescriptorLocked() {
    if (!LoadChannel0DescriptorLocked()) return;
    if (!dma_->IsPalette(0)) {
        RequireWholeFrameDescriptorLocked();
        return;
    }
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-63 bit 26 PAL: palette
       data for the palette RAM; bit 21 EOFINT: EOF when the length reaches 0. */
    const uint32_t before = UnmaskedStatusLocked();
    if (dma_->Channel0EndOfFrame()) lcsr0_ |= kLcsr0Eof0;
    LatchInterruptIdLocked(before, dma_->Channel0FrameId());
    if (!LoadChannel0DescriptorLocked()) return;
    if (dma_->IsPalette(0)) {
        emu_.Get<Fatal>().Die("Pxa27xLcd: channel 0 palette descriptor chains to another "
                              "palette descriptor (FSADR0 0x%08X)", dma_->SrcPa(0));
    }
    RequireWholeFrameDescriptorLocked();
}

const char* Pxa27xLcd::UnmodelledScanLocked() const {
    const uint32_t pcd = lccr_[3] & kLccr3PcdMask;
    if (!(lccr_[0] & kLccr0Pas))  return "passive-mode timing (PAS 0)";
    if (lccr_[0] & kLccr0Sds)     return "dual-scan timing (SDS 1)";
    if (lccr_[0] & kLccr0Lcdt)    return "an internal-frame-buffer panel (LCDT 1)";
    if (lccr_[3] & kLccr3ApiMask) return "the AC bias count interrupt (LCCR3 API)";
    /* Intel PXA27x Developer's Manual 280000-001 Section 7.4.3 Note and Table
       7-43 DPC: PCD minimum 1 with PCDDIV, 2 with DPC. */
    if ((lccr_[4] & kLccr4Pcddiv) && pcd < 1u) return "PCDDIV with PCD 0";
    if ((lccr_[3] & kLccr3Dpc) && pcd < 2u)    return "DPC with PCD below 2";
    return nullptr;
}

/* Intel PXA27x Developer's Manual 280000-001 Section 7.4.3 and Table 7-44:
   pixel clock LCLK/(2(PCD+1)), or LCLK/(PCD+1) with PCDDIV. */
RasterScanPeripheral::ScanShape Pxa27xLcd::ScanShapeLocked() const {
    const uint64_t pcd = lccr_[3] & kLccr3PcdMask;
    const uint64_t div = (lccr_[4] & kLccr4Pcddiv) ? pcd + 1u : 2u * (pcd + 1u);
    return ScanShape{{emu_.Get<Pxa27xClockManager>().LcdClockHz(), div}, ScanFrameLocked()};
}

/* Intel PXA27x Developer's Manual 280000-001 Tables 7-41, 7-42, Figure 7-36,
   Table 7-58 LDD: the frame edge follows line LPP's PPL span. */
RasterScanClock::Frame Pxa27xLcd::ScanFrameLocked() const {
    using cerf::BitField;
    const uint64_t head  = BitField(lccr_[1], 10u, 0x3Fu) + 1u + BitField(lccr_[1], 24u, 0xFFu)
                         + 1u + BitField(lccr_[1], 0u, 0x3FFu) + 1u;
    const uint64_t line  = head + BitField(lccr_[1], 16u, 0xFFu) + 1u;
    const uint64_t above = BitField(lccr_[2], 10u, 0x3Fu) + 1u + BitField(lccr_[2], 24u, 0xFFu)
                         + BitField(lccr_[2], 0u, 0x3FFu);
    RasterScanClock::Frame f;
    f.ticks   = line * (above + 1u + BitField(lccr_[2], 16u, 0xFFu));
    f.edge[0] = line * above + head;
    f.edges   = 1u;
    return f;
}

/* Intel PXA27x Developer's Manual 280000-001 Table 7-40 DIS, Table 7-58 bits 0-2
   and Table 7-63 PAL. */
bool Pxa27xLcd::EdgeRaisesInterruptLocked(uint32_t, bool) const {
    if (!(lccr_[0] & kLccr0Dis) || !(lccr_[0] & kLccr0Ldm)) return true;
    return !(lccr_[0] & kLccr0Eofm0) && dma_->Channel0EndOfFrame();
}

void Pxa27xLcd::FrameEdgeLocked(uint32_t) {
    if (dma_->Halted()) {
        emu_.Get<Fatal>().Die("Pxa27xLcd: frame ends with the channel 0 DMA halted by a bus "
                              "error; the scan without DMA data is not modelled");
    }
    /* Intel PXA27x Developer's Manual 280000-001 Table 7-58 bit 8 EOF0: set
       when the DMA finished fetching a frame and the channel 0 Descriptor has
       EOFINT set. */
    const uint32_t before = UnmaskedStatusLocked();
    if (dma_->Channel0EndOfFrame()) lcsr0_ |= kLcsr0Eof0;
    LatchInterruptIdLocked(before, dma_->Channel0FrameId());

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-40 bit 10 DIS and Table
       7-58 bit 0 LDD: the frame completes, then LDD sets and ENB clears. */
    if (lccr_[0] & kLccr0Dis) {
        lccr_[0] &= ~kLccr0Enb;
        lcsr0_   |= kLcsr0Ldd;
        StopScanLocked();
        return;
    }
    LoadFrameDescriptorLocked();
}

uint32_t* Pxa27xLcd::RegSlotLocked(uint32_t off) {
    switch (off) {
    case kLccr0: case kLccr1: case kLccr2:
    case kLccr3: case kLccr4: case kLccr5: return &lccr_[off / 4u];
    case kLcsr0:  return &lcsr0_;
    case kLcsr1:  return &lcsr1_;
    case kLiidr:  return &liidr_;
    case kTrgbr:  return &trgbr_;
    case kTcr:    return &tcr_;
    case kOvl1c1: return &ovl1c1_;
    case kOvl1c2: return &ovl1c2_;
    case kOvl2c1: return &ovl2c1_;
    case kOvl2c2: return &ovl2c2_;
    case kCcr:    return &ccr_;
    case kCmdcr:  return &cmdcr_;
    case kPrsr:   return &prsr_;
    default:
        emu_.Get<Fatal>().Die("Pxa27xLcd: register offset 0x%03X has no storage slot", off);
    }
}

/* Intel PXA27x Developer's Manual 280000-001 Section 7.5.3: the controller must
   be disabled when an LCCR1 field changes; Table 7-40 ENB: all control
   registers are initialized before ENB is set. */
void Pxa27xLcd::RequireStableTimingLocked(uint32_t off, uint32_t value) const {
    if (!(lccr_[0] & kLccr0Enb)) return;
    uint32_t mask = 0u;
    switch (off) {
    case kLccr1: mask = 0xFFFFFFFFu;  break;
    case kLccr2: mask = 0xFFFFFFFFu;  break;
    case kLccr3: mask = kLccr3Timing; break;
    case kLccr4: mask = kLccr4Pcddiv; break;
    default: return;
    }
    if (((lccr_[off / 4u] ^ value) & mask) != 0u) {
        emu_.Get<Fatal>().Die("Pxa27xLcd: LCCR%u write 0x%08X over 0x%08X changes scan timing "
                              "while ENB is set", off / 4u, value, lccr_[off / 4u]);
    }
}

void Pxa27xLcd::RequirePlaneDisabled(const char* reg, uint32_t value, uint32_t enable) const {
    if (value & enable) {
        emu_.Get<Fatal>().Die("Pxa27xLcd: %s write 0x%08X enables a plane whose DMA and "
                              "scan-out are not modelled", reg, value);
    }
}

void Pxa27xLcd::WriteLccr0Locked(uint32_t value, uint64_t now) {
    const uint32_t old         = lccr_[0];
    const bool     was_enabled = (old & kLccr0Enb) != 0;
    if (was_enabled && (value & kLccr0Enb) && ((old ^ value) & kLccr0Timing) != 0u) {
        emu_.Get<Fatal>().Die("Pxa27xLcd: LCCR0 write 0x%08X over 0x%08X changes scan timing "
                              "while ENB is set", value, old);
    }
    lccr_[0] = value;

    if (!was_enabled) {
        if (!(value & kLccr0Enb)) return;
        if (value & kLccr0Dis) {
            emu_.Get<Fatal>().Die("Pxa27xLcd: LCCR0 0x%08X sets ENB and DIS together; a scan "
                                  "that starts while disabling is not modelled", value);
        }
        if (const char* why = UnmodelledScanLocked()) {
            emu_.Get<Fatal>().Die("Pxa27xLcd: LCCR0 0x%08X LCCR3 0x%08X LCCR4 0x%08X enables %s",
                                  lccr_[0], lccr_[3], lccr_[4], why);
        }
        if (!emu_.Get<Pxa27xClockManager>().LcdClockEnabled()) {
            emu_.Get<Fatal>().Die("Pxa27xLcd: LCCR0 ENB with CKEN[16] gating the LCD clock; a "
                                  "scan that starts without its clock is not modelled");
        }
        LoadFrameDescriptorLocked();
        StartScanLocked(now);
        return;
    }

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-58 bit 7 QD: set when
       ENB is cleared and the DMA finishes its current data burst; Table 7-40
       LDM: clearing ENB forces a "quick reset" and LDD is not set. */
    if (!(value & kLccr0Enb)) {
        lcsr0_ |= kLcsr0Qd;
        StopScanLocked();
    }
}

void Pxa27xLcd::WriteRegLocked(uint32_t off, uint32_t value, uint64_t now) {
    if (Pxa27xLcdDma::Decodes(off)) {
        dma_->Write(off, value);
        return;
    }
    RequireStableTimingLocked(off, value);
    switch (off) {
    case kLccr0: WriteLccr0Locked(value, now); return;
    case kLcsr0: lcsr0_ &= ~(value & kLcsr0StickyMask); return;
    case kLcsr1: lcsr1_ &= ~value; return;
    case kLiidr: return;
    case kOvl1c1: RequirePlaneDisabled("OVL1C1", value, kOvl1c1O1en); break;
    case kOvl2c1: RequirePlaneDisabled("OVL2C1", value, kOvl2c1O2en); break;
    case kCcr:    RequirePlaneDisabled("CCR", value, kCcrCen);        break;
    default: break;
    }
    *RegSlotLocked(off) = value;
}

uint32_t Pxa27xLcd::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    uint32_t value;
    bool     edged;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        edged = CatchUpLocked(ScanNow());
        value = Pxa27xLcdDma::Decodes(off) ? dma_->Read(off) : *RegSlotLocked(off);
    }
    if (edged) ScanEdgesRan();
    return value;
}

void Pxa27xLcd::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    bool enabled_edge;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        const uint64_t now = ScanNow();
        CatchUpLocked(now);
        const bool was_enabled = (lccr_[0] & kLccr0Enb) != 0;
        WriteRegLocked(off, value, now);
        RearmScanLocked();
        enabled_edge = !was_enabled && (lccr_[0] & kLccr0Enb) != 0;
    }
    ScanEdgesRan();
    /* Intel PXA27x Developer's Manual 280000-001 Section 7.5.2 (page 7-55):
       "in the control registers must be programmed before setting
       LCCR0[ENB]". */
    if (enabled_edge) emu_.Get<HostWindow>().OnLcdEnabled();
}

template <typename F>
void Pxa27xLcd::VisitRegs(F& f) {
    for (uint32_t i = 0; i < 6u; ++i) f("lccr", lccr_[i]);
    f("lcsr0", lcsr0_);
    f("lcsr1", lcsr1_);
    f("liidr", liidr_);
    f("trgbr", trgbr_);
    f("tcr", tcr_);
    f("cmdcr", cmdcr_);
    f("prsr", prsr_);
    f("ovl1c1", ovl1c1_);
    f("ovl1c2", ovl1c2_);
    f("ovl2c1", ovl2c1_);
    f("ovl2c2", ovl2c2_);
    f("ccr", ccr_);
}

void Pxa27xLcd::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    StateWriteField f(w);
    VisitRegs(f);
    dma_->SaveState(w);
    SaveScanLocked(w);
}

void Pxa27xLcd::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    StateReadField f(r);
    VisitRegs(f);
    dma_->RestoreState(r);
    RestoreScanLocked(r);
}

void Pxa27xLcd::PostRestore() {
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        const uint64_t now = ScanNow();
        ResumeScanLocked(now);
        GateScanLocked(emu_.Get<Pxa27xClockManager>().LcdClockEnabled(), now);
    }
    ScanEdgesRan();
}

REGISTER_SERVICE(Pxa27xLcd);
