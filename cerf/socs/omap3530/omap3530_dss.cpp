#include "omap3530_dss.h"

#include "../../boards/board_context.h"
#include "omap3530_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../host/host_window.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"
#include "omap3530_cm_dss.h"

bool Omap3530Dss::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Omap3530;
}

void Omap3530Dss::OnReady() {
    cm_dss_ = &emu_.Get<Omap3530CmDss>();
    AttachScanClock();
    cm_dss_->RegisterDss1Listener([this] {
        OnScanFunctionalClockChange(cm_dss_->Dss1FclkEnabled());
    });
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        std::lock_guard<std::mutex> lk(state_mtx_);
        StopScanLocked();
        ApplyScanResetsLocked();
        RecomputeIrqLineLocked();
    });
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        ApplyScanResetsLocked();
    }
    emu_.Get<PeripheralDispatcher>().Register(this);
    dss_top_[kDssSysstatus / 4u]   = kSysstatusResetDone;
    dispc_  [kDispcSysstatus / 4u] = kSysstatusResetDone;
}

/* Tables 15-145 and 15-149 (printed p. 2447-2450): DSS_CONTROL and DSS_PLL_CONTROL
   reset to 0. */
void Omap3530Dss::ApplyScanResetsLocked() {
    dss_top_[kDssControl / 4u] = 0u;
    dss_top_[kDssPllCtrl / 4u] = 0u;
    ApplyDispcScanResetsLocked();
}

/* Tables 15-159, 15-161, 15-163, 15-175, 15-177, 15-181 and 15-187 (printed
   p. 2454-2473): reset values of the registers the LCD scan reads. */
void Omap3530Dss::ApplyDispcScanResetsLocked() {
    dispc_[kDispcControl   / 4u] = 0u;
    dispc_[kDispcIrqstatus / 4u] = 0u;
    dispc_[kDispcIrqenable / 4u] = 0u;
    dispc_[kDispcTimingH   / 4u] = 0u;
    dispc_[kDispcTimingV   / 4u] = 0u;
    dispc_[kDispcDivisor   / 4u] = kDivisorReset;
    dispc_[kDispcSizeLcd   / 4u] = 0u;
}

bool Omap3530Dss::ShouldAssertIrqLocked() const {
    return (dispc_[kDispcIrqstatus / 4u] &
            dispc_[kDispcIrqenable / 4u] &
            kIrqMask) != 0u;
}

void Omap3530Dss::RecomputeIrqLineLocked() {
    const bool want_high = ShouldAssertIrqLocked();
    auto& intc = emu_.Get<IrqController>();
    if (want_high) intc.AssertIrq  (kIrqDss);
    else           intc.DeAssertIrq(kIrqDss);
}

const char* Omap3530Dss::UnmodelledLcdLocked() const {
    const uint32_t ctrl = dispc_[kDispcControl / 4u];
    const uint32_t div  = dispc_[kDispcDivisor / 4u];
    if (dss_top_[kDssControl / 4u] & kDispcClkSwitch) return "DISPC_CLK_SWITCH on DSI1_PLL_FCLK";
    if (!(ctrl & kCtrlStnTft))          return "a passive-matrix panel";
    if (ctrl & kCtrlStallMode)          return "STALLMODE";
    if (ctrl & kCtrlTdmEnable)          return "the TDM multiple-cycle format";
    if (((div >> 16) & 0xFFu) == 0u)    return "the invalid DIVISOR LCD 0";
    if ((div & 0xFFu) < 2u)             return "the invalid DIVISOR PCD 0 or 1";
    return nullptr;
}

/* SPRUF98Y §15.6.2.6 (printed p. 2389) and Figures 15-17..15-20 (printed
   p. 2167): a line is HSW, HBP, PPL pixels, HFP; a frame is VSW, VBP, LPP lines,
   VFP. */
RasterScanClock::Frame Omap3530Dss::ScanFrameLocked() const {
    const uint32_t th = dispc_[kDispcTimingH / 4u];
    const uint32_t tv = dispc_[kDispcTimingV / 4u];
    const uint32_t sz = dispc_[kDispcSizeLcd / 4u];
    const uint64_t line = uint64_t(th & 0xFFu) + 1u + ((th >> 8) & 0xFFFu) + 1u +
                          ((th >> 20) & 0xFFFu) + 1u + (sz & 0x7FFu) + 1u;
    const uint64_t vfp  = VfpLinesLocked();
    const uint64_t active_end = (uint64_t(tv & 0xFFu) + 1u + ((tv >> 20) & 0xFFFu) +
                                 ((sz >> 16) & 0x7FFu) + 1u) * line;
    RasterScanClock::Frame f;
    f.ticks = active_end + vfp * line;
    if (vfp != 0u) {
        f.edge[0] = active_end;
        f.edge[1] = f.ticks;
        f.edges   = 2u;
    } else {
        f.edge[0] = f.ticks;
        f.edges   = 1u;
    }
    return f;
}

/* Table 15-181: pixel clock = functional clock / LCD / PCD. */
RasterScanPeripheral::ScanShape Omap3530Dss::ScanShapeLocked() const {
    const uint32_t div = dispc_[kDispcDivisor / 4u];
    const GuestCycleClock::Rate fclk = cm_dss_->Dss1AlwonFclk();
    return ScanShape{{fclk.num, fclk.den * ((div >> 16) & 0xFFu) * (div & 0xFFu)},
                     ScanFrameLocked()};
}

uint32_t Omap3530Dss::VfpLinesLocked() const {
    return (dispc_[kDispcTimingV / 4u] >> 8) & 0xFFFu;
}

/* Table 15-163 (printed p. 2461): LCDENABLE 0x0 "LCD output disabled (at the end of
   the frame when the bit is reset)"; GOLCD updates "at the VFP start period". */
bool Omap3530Dss::EdgeRaisesInterruptLocked(uint32_t edge_index, bool) const {
    const bool two_edges = VfpLinesLocked() != 0u;
    if (two_edges && edge_index == 0u) return false;
    const uint32_t enable = dispc_[kDispcIrqenable / 4u];
    if (enable & kIrqVsync) return true;
    return (enable & kIrqFrameDone) != 0u && !(dispc_[kDispcControl / 4u] & kCtrlLcdEnable);
}

void Omap3530Dss::FrameEdgeLocked(uint32_t edge_index) {
    const bool two_edges = VfpLinesLocked() != 0u;
    if (!two_edges || edge_index == 0u) dispc_[kDispcControl / 4u] &= ~kCtrlGoLcd;
    if (two_edges && edge_index == 0u) return;
    dispc_[kDispcIrqstatus / 4u] |= kIrqVsync;
    if (dispc_[kDispcControl / 4u] & kCtrlLcdEnable) return;
    dispc_[kDispcIrqstatus / 4u] |= kIrqFrameDone;
    StopScanLocked();
}

void Omap3530Dss::ScanEdgesRan() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    RecomputeIrqLineLocked();
}

void Omap3530Dss::HandleDssSysconfigWriteLocked(uint32_t value) {
    if (ScanActiveLocked() && (value & kSysconfigSoftReset)) {
        emu_.Get<Fatal>().Die("Omap3530Dss: DSS soft reset while the LCD scans is not modelled");
    }
    dss_top_[kDssSysconfig / 4u] = value & ~kSysconfigSoftReset;
    if (value & kSysconfigSoftReset) {
        dss_top_[kDssSysstatus / 4u] = kSysstatusResetDone;
        ApplyScanResetsLocked();
        RecomputeIrqLineLocked();
    }
}

void Omap3530Dss::HandleDssControlWriteLocked(uint32_t value) {
    if (ScanActiveLocked() && ((dss_top_[kDssControl / 4u] ^ value) & kDispcClkSwitch)) {
        emu_.Get<Fatal>().Die("Omap3530Dss: DISPC_CLK_SWITCH changes while the LCD scans; not "
                              "modelled");
    }
    dss_top_[kDssControl / 4u] = value;
}

/* Table 15-151: the DSS_SDI_STATUS SDI PLL fields reset to 0. */
uint32_t Omap3530Dss::SdiStatusLocked() const {
    const uint32_t ctrl = dss_top_[kDssControl / 4u];
    const uint32_t pll  = dss_top_[kDssPllCtrl / 4u];
    if (ctrl & (kDispcClkSwitch | kDsiClkSwitch)) {
        emu_.Get<Fatal>().Die("Omap3530Dss: DSS_SDI_STATUS read with DSS_CONTROL 0x%08X selecting "
                              "a DSI PLL clock; the DSI PLL is not modelled", ctrl);
    }
    if (pll & (kSdiPllGoBit | kSdiPllSysReset)) {
        emu_.Get<Fatal>().Die("Omap3530Dss: DSS_SDI_STATUS read with the SDI PLL out of reset "
                              "(DSS_PLL_CONTROL 0x%08X); the SDI PLL is not modelled", pll);
    }
    return kSdiStatusDispcAlwon | kSdiStatusDsiAlwon;
}

uint32_t Omap3530Dss::DispcLineStatusLocked(uint64_t now) const {
    const unsigned long long tick = ScanLiveLocked() ? ScanTickInFrameLocked(now) : 0ull;
    emu_.Get<Fatal>().Die("Omap3530Dss: DISPC_LINE_STATUS read (scan live %d, tick %llu in "
                          "frame) is not modelled", ScanLiveLocked() ? 1 : 0, tick);
}

void Omap3530Dss::HandleDispcSysconfigWriteLocked(uint32_t value) {
    dispc_[kDispcSysconfig / 4u] = value & ~kSysconfigSoftReset;
    if (value & kSysconfigSoftReset) {
        StopScanLocked();
        for (auto& w : dispc_) w = 0u;
        dispc_[kDispcSysstatus / 4u] = kSysstatusResetDone;
        ApplyDispcScanResetsLocked();
        emu_.Get<IrqController>().DeAssertIrq(kIrqDss);
    }
}

void Omap3530Dss::HandleDispcIrqstatusWriteLocked(uint32_t value) {
    dispc_[kDispcIrqstatus / 4u] &= ~(value & kIrqMask);
    RecomputeIrqLineLocked();
}

void Omap3530Dss::HandleDispcIrqenableWriteLocked(uint32_t value) {
    if (value & kIrqUnproducedEvents) {
        emu_.Get<Fatal>().Die("Omap3530Dss: IRQENABLE 0x%08X enables a scan event the model "
                              "does not produce (mask 0x%08X)", value, kIrqUnproducedEvents);
    }
    dispc_[kDispcIrqenable / 4u] = value & kIrqMask;
    RearmScanLocked();
    RecomputeIrqLineLocked();
}

bool Omap3530Dss::HandleDispcControlWriteLocked(uint32_t value, uint64_t now) {
    const uint32_t old = dispc_[kDispcControl / 4u];
    if (!(old & kCtrlDigitalEnable) && (value & kCtrlDigitalEnable)) {
        emu_.Get<Fatal>().Die("Omap3530Dss: DIGITALENABLE (CONTROL 0x%08X); the digital (VENC) "
                              "output timing is not modelled", value);
    }
    if (ScanActiveLocked() && ((old ^ value) & kCtrlScanModeBits)) {
        emu_.Get<Fatal>().Die("Omap3530Dss: CONTROL 0x%08X -> 0x%08X changes STNTFT/STALLMODE/"
                              "TDMENABLE while the LCD scans; the shadow update is not "
                              "modelled", old, value);
    }
    dispc_[kDispcControl / 4u] = value;
    RearmScanLocked();
    if ((old & kCtrlLcdEnable) || !(value & kCtrlLcdEnable)) return false;
    if (!ScanActiveLocked()) {
        if (const char* why = UnmodelledLcdLocked()) {
            emu_.Get<Fatal>().Die("Omap3530Dss: LCD output with %s is not modelled (CONTROL "
                                  "0x%08X DIVISOR 0x%08X DSS_CONTROL 0x%08X)", why, value,
                                  dispc_[kDispcDivisor / 4u], dss_top_[kDssControl / 4u]);
        }
        if (!cm_dss_->Dss1FclkEnabled()) {
            emu_.Get<Fatal>().Die("Omap3530Dss: LCDENABLE with EN_DSS1 gating DSS1_ALWON_FCLK; "
                                  "a scan that starts without its clock is not modelled");
        }
        StartScanLocked(now);
    }
    return true;
}

void Omap3530Dss::HandleDispcScanTimingWriteLocked(uint32_t doff, uint32_t value) {
    if (ScanActiveLocked() && dispc_[doff / 4u] != value) {
        emu_.Get<Fatal>().Die("Omap3530Dss: +0x%03X 0x%08X -> 0x%08X while the LCD scans; the "
                              "shadow update is not modelled", doff, dispc_[doff / 4u], value);
    }
    dispc_[doff / 4u] = value;
}

uint32_t Omap3530Dss::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off & 3u) HaltUnsupportedAccess("ReadWord (misaligned)", addr, 0);

    std::lock_guard<std::mutex> lk(state_mtx_);
    const uint64_t now = ScanNow();
    if (CatchUpLocked(now)) RecomputeIrqLineLocked();

    if (off < kDispcBase) {
        const uint32_t v = off == kDssSdiStatus ? SdiStatusLocked() : dss_top_[off / 4u];
        LOG(Periph, "[DSS] R off=0x%03X -> 0x%08X\n", off, v);
        return v;
    }
    if (off < kRfbiBase) {
        const uint32_t doff = off - kDispcBase;
        const uint32_t v = doff == kDispcLineStatus ? DispcLineStatusLocked(now)
                                                    : dispc_[doff / 4u];
        LOG(Periph, "[DISPC] R off=0x%03X -> 0x%08X\n", doff, v);
        return v;
    }
    if (off < kVencBase) {
        const uint32_t v = rfbi_[(off - kRfbiBase) / 4u];
        LOG(Periph, "[RFBI] R off=0x%03X -> 0x%08X (stub)\n",
            off - kRfbiBase, v);
        return v;
    }
    const uint32_t v = venc_[(off - kVencBase) / 4u];
    LOG(Periph, "[VENC] R off=0x%03X -> 0x%08X (stub)\n",
        off - kVencBase, v);
    return v;
}

uint16_t Omap3530Dss::ReadHalf(uint32_t addr) {
    const uint32_t aligned = addr & ~3u;
    const uint32_t word = ReadWord(aligned);
    return static_cast<uint16_t>((word >> ((addr & 2u) * 8u)) & 0xFFFFu);
}

void Omap3530Dss::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off & 3u) HaltUnsupportedAccess("WriteWord (misaligned)", addr, value);

    if (off >= kDispcBase && off < kRfbiBase
        && (off - kDispcBase) == kDispcControl) {
        bool lcd_on;
        {
            std::lock_guard<std::mutex> lk(state_mtx_);
            const uint64_t now = ScanNow();
            if (CatchUpLocked(now)) RecomputeIrqLineLocked();
            lcd_on = HandleDispcControlWriteLocked(value, now);
        }
        LOG(Periph, "[DISPC] W off=0x%03X <- 0x%08X\n", kDispcControl, value);
        if (lcd_on) emu_.Get<HostWindow>().OnLcdEnabled();
        return;
    }

    std::lock_guard<std::mutex> lk(state_mtx_);
    if (CatchUpLocked(ScanNow())) RecomputeIrqLineLocked();

    if (off < kDispcBase) {
        LOG(Periph, "[DSS] W off=0x%03X <- 0x%08X\n", off, value);
        switch (off) {
        case kDssSysconfig: HandleDssSysconfigWriteLocked(value); return;
        case kDssControl:   HandleDssControlWriteLocked(value);   return;
        case kDssRev:
        case kDssSysstatus:
        case kDssSdiStatus:
            return;
        default:
            dss_top_[off / 4u] = value;
            return;
        }
    }
    if (off < kRfbiBase) {
        const uint32_t doff = off - kDispcBase;
        LOG(Periph, "[DISPC] W off=0x%03X <- 0x%08X\n", doff, value);
        switch (doff) {
        case kDispcSysconfig: HandleDispcSysconfigWriteLocked(value); return;
        case kDispcIrqstatus: HandleDispcIrqstatusWriteLocked(value); return;
        case kDispcIrqenable: HandleDispcIrqenableWriteLocked(value); return;
        case kDispcTimingH:
        case kDispcTimingV:
        case kDispcDivisor:
        case kDispcSizeLcd:   HandleDispcScanTimingWriteLocked(doff, value); return;
        case kDispcRev:
        case kDispcSysstatus:
        case kDispcLineStatus:
            return;
        default:
            dispc_[doff / 4u] = value;
            return;
        }
    }
    if (off < kVencBase) {
        rfbi_[(off - kRfbiBase) / 4u] = value;
        LOG(Periph, "[RFBI] W off=0x%03X <- 0x%08X (stub)\n",
            off - kRfbiBase, value);
        return;
    }
    venc_[(off - kVencBase) / 4u] = value;
    LOG(Periph, "[VENC] W off=0x%03X <- 0x%08X (stub)\n",
        off - kVencBase, value);
}

bool Omap3530Dss::IsScanning() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    return (dispc_[kDispcControl    / 4u] & kCtrlLcdEnable)  != 0u
        && (dispc_[kDispcGfxAttribs / 4u] & kGfxAttrEnable) != 0u;
}

uint32_t Omap3530Dss::GetFbPa() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    return dispc_[kDispcGfxBa0 / 4u];
}

uint32_t Omap3530Dss::GetGuestW() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    return (dispc_[kDispcSizeLcd / 4u] & 0x7FFu) + 1u;
}

uint32_t Omap3530Dss::GetGuestH() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    return ((dispc_[kDispcSizeLcd / 4u] >> 16) & 0x7FFu) + 1u;
}

uint32_t Omap3530Dss::GetGfxFormat() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    return (dispc_[kDispcGfxAttribs / 4u] >> 1) & 0xFu;
}

void Omap3530Dss::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    w.WriteBytes("dss_top", dss_top_, sizeof(dss_top_));
    w.WriteBytes("dispc", dispc_,   sizeof(dispc_));
    w.WriteBytes("rfbi", rfbi_,    sizeof(rfbi_));
    w.WriteBytes("venc", venc_,    sizeof(venc_));
    SaveScanLocked(w);
}

void Omap3530Dss::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    r.ReadBytes("dss_top", dss_top_, sizeof(dss_top_));
    r.ReadBytes("dispc", dispc_,   sizeof(dispc_));
    r.ReadBytes("rfbi", rfbi_,    sizeof(rfbi_));
    r.ReadBytes("venc", venc_,    sizeof(venc_));
    RestoreScanLocked(r);
}

void Omap3530Dss::PostRestore() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    const uint64_t now = ScanNow();
    ResumeScanLocked(now);
    GateScanLocked(cm_dss_->Dss1FclkEnabled(), now);
    RecomputeIrqLineLocked();
}

REGISTER_SERVICE(Omap3530Dss);
