#include "imx31_ccm.h"

#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "imx31_clock_input.h"

#include <cstdint>
#include "imx31_id.h"

namespace {

constexpr uint32_t kSlotCount = Imx31Ccm::kSlotCount;

/* MCIMX31RM Table 3-1 reset values; CCMR is the Figure 3-3 reset row, whose PRCS the CLKSS
   strap sets (Table 3-1 note 1). */
constexpr uint32_t kResetValues[kSlotCount] = {
    0x074B0B79u,   /* 0x00 CCMR    */
    0xFF870B48u,   /* 0x04 PDR0    */
    0x49FCFE7Fu,   /* 0x08 PDR1    */
    0x007F0000u,   /* 0x0C RCSR    */
    0x04001800u,   /* 0x10 MPCTL   */
    0x04051C03u,   /* 0x14 UPCTL   */
    0x04043001u,   /* 0x18 SPCTL   */
    0x00000280u,   /* 0x1C COSR    */
    0xFFFFFFFFu,   /* 0x20 CGR0    */
    0xFFFFFFFFu,   /* 0x24 CGR1    */
    0xFFFFFFFFu,   /* 0x28 CGR2    */
    0xFFFFFFFFu,   /* 0x2C WIMR0   */
    0x0000000Fu,   /* 0x30 LDC     */
    0x00000000u,   /* 0x34 DCVR0   */
    0x00000000u,   /* 0x38 DCVR1   */
    0x00000000u,   /* 0x3C DCVR2   */
    0x00000000u,   /* 0x40 DCVR3   */
    0x00000000u,   /* 0x44 LTR0    */
    0x00004040u,   /* 0x48 LTR1    */
    0x00000000u,   /* 0x4C LTR2    */
    0x00000000u,   /* 0x50 LTR3    */
    0x00000000u,   /* 0x54 LTBR0   (R only) */
    0x00000000u,   /* 0x58 LTBR1   (R only) */
    0x80209828u,   /* 0x5C PMCR0   */
    0x00AA0000u,   /* 0x60 PMCR1   */
    0x00000285u,   /* 0x64 PDR2    */
};

constexpr uint32_t kRcsrSlot  =  3u;
constexpr uint32_t kLtbr0Slot = 21u;
constexpr uint32_t kLtbr1Slot = 22u;
constexpr uint32_t kPmcr0Slot = 23u;
constexpr uint32_t kPmcr0DptenBit = 1u << 0;
constexpr uint32_t kPmcr0DvfenBit = 1u << 4;

constexpr uint32_t kCcmrSlot  = 0u;
constexpr uint32_t kPdr0Slot  = 1u;
constexpr uint32_t kPdr1Slot  = 2u;
constexpr uint32_t kMpctlSlot = 4u;
constexpr uint32_t kUpctlSlot = 5u;
constexpr uint32_t kSpctlSlot = 6u;
constexpr uint32_t kCgr0Slot  = 8u;
constexpr uint32_t kCgr1Slot  = 9u;
constexpr uint32_t kCgr2Slot  = 10u;
constexpr uint32_t kLdcSlot   = 12u;

/* MCIMX31RM Table 3-7 RCSR: GPF [7:5] is reset by reset_in_por only; REST [2:0]
   000 POR, 001 qualified external reset, 010 watchdog time-out. */
constexpr uint32_t kRcsrGpfMask  = 0x7u << 5;
constexpr uint32_t kRcsrRestMask = 0x7u;
constexpr uint32_t kRestPor      = 0u;
constexpr uint32_t kRestExternal = 1u;
constexpr uint32_t kRestWatchdog = 2u;

/* MCIMX31RM Table 3-4 CCMR: PERCS [24] (1 = ipg_clk), MDS [7], LPM [15:14], PRCS [2:1]
   (01 FPM, 10 CKIH). */
constexpr uint32_t kCcmrPercs     = 1u << 24;
constexpr uint32_t kCcmrMds       = 1u << 7;
constexpr uint32_t kCcmrLpmShift  = 14;
constexpr uint32_t kCcmrLpmMask   = 0x3u << kCcmrLpmShift;
constexpr uint32_t kLpmWait       = 0u;
constexpr uint32_t kLpmDoze       = 1u;
constexpr uint32_t kLpmRetention  = 2u;
constexpr uint32_t kLpmDeepSleep  = 3u;
constexpr uint32_t kCcmrPrcsFpm   = 1u << 1;
constexpr uint32_t kCcmrPrcsCkih  = 2u << 1;

constexpr uint32_t kPllSlots[] = {kMpctlSlot, kUpctlSlot, kSpctlSlot};

}  /* namespace */

bool Imx31Ccm::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx31;
}

void Imx31Ccm::OnReady() {
    input_ = &emu_.Get<Imx31ClockInput>();
    LoadResetValues();
    plls_ = &emu_.Get<Imx31Plls>();
    plls_->Attach(regs_[kCcmrSlot], PllControls());
    plls_->RegisterChangeListener([this] { ApplyRates(); });
    auto& reset = emu_.Get<GuestCpuReset>();
    reset.SetCauseLatch(this);
    reset.RegisterResetListener([this](ResetLineKind kind) { ResetRegisters(kind); });
    reset.RegisterResetReleaseListener([this] {
        ApplyRates();
        NotifyGates();
    });
    auto& clock = emu_.Get<GuestCycleClock>();
    clock.RegisterIdleListener([this] { OnIdle(); });
    clock.RegisterIdleExitListener([this] { OnIdleExit(); });
    emu_.Get<PeripheralDispatcher>().Register(this);
    ApplyRates();
}

void Imx31Ccm::LatchColdReset()     { latched_rest_.store(kRestPor, std::memory_order_release); }
void Imx31Ccm::LatchWarmReset()     { latched_rest_.store(kRestExternal, std::memory_order_release); }
void Imx31Ccm::LatchWatchdogReset() { latched_rest_.store(kRestWatchdog, std::memory_order_release); }

/* MCIMX31RM 3.6.5: on a watchdog reset every CCM register returns to its default
   except those reset by por_reset only (Table 3-7 RCSR GPF; LDC "only after POR"). */
void Imx31Ccm::ResetRegisters(ResetLineKind kind) {
    const bool     por  = kind == ResetLineKind::Rtc;
    const uint32_t gpf  = por ? 0u : regs_[kRcsrSlot] & kRcsrGpfMask;
    const uint32_t ldc  = regs_[kLdcSlot];
    LoadResetValues();
    regs_[kRcsrSlot] = (kResetValues[kRcsrSlot] & ~(kRcsrGpfMask | kRcsrRestMask)) | gpf |
                       latched_rest_.load(std::memory_order_acquire);
    if (!por) regs_[kLdcSlot] = ldc;
    plls_->Settle(regs_[kCcmrSlot], PllControls());
}

void Imx31Ccm::LoadResetValues() {
    for (uint32_t i = 0; i < kSlotCount; ++i) regs_[i] = kResetValues[i];
    regs_[kCcmrSlot] |= input_->ResetReferenceIsCkih() ? kCcmrPrcsCkih : kCcmrPrcsFpm;
}

Imx31Plls::Controls Imx31Ccm::PllControls() const {
    Imx31Plls::Controls ctl{};
    for (uint32_t p = 0; p < Imx31Plls::kCount; ++p) ctl[p] = regs_[kPllSlots[p]];
    return ctl;
}

/* Figure 3-24: mcu_clk is mcu_main_clk through the mcu divider, Table 3-5 MCU_PODF
   [2:0], value + 1. */
uint64_t Imx31Ccm::McuClkHz() const {
    return DividedHz(McuMainClkHz(), (regs_[kPdr0Slot] & 0x7u) + 1u, "mcu_clk");
}

uint64_t Imx31Ccm::DividedHz(uint64_t hz, uint64_t divider, const char* clock) const {
    if (hz % divider != 0u) {
        emu_.Get<Fatal>().Die("Imx31Ccm: %s = %llu Hz / %llu is not a whole number of Hz", clock,
                              static_cast<unsigned long long>(hz),
                              static_cast<unsigned long long>(divider));
    }
    return hz / divider;
}

void Imx31Ccm::ApplyRates() {
    auto& clock = emu_.Get<GuestCycleClock>();
    clock.SetClockHz(McuClkHz());
    const uint64_t hz = clock.CpuHz();
    if (hz != applied_hz_) {
        LOG(SocClkpwr, "Imx31Ccm: core clock %llu -> %llu Hz (CCMR %08X PDR0 %08X MPCTL %08X)\n",
            static_cast<unsigned long long>(applied_hz_), static_cast<unsigned long long>(hz),
            regs_[kCcmrSlot], regs_[kPdr0Slot], regs_[kMpctlSlot]);
        applied_hz_ = hz;
    }
    for (auto& fn : listeners_) fn();
}

void Imx31Ccm::RegisterRateListener(std::function<void()> fn) {
    listeners_.push_back(std::move(fn));
}

void Imx31Ccm::RegisterGate1Listener(std::function<void()> fn) {
    gate1_listeners_.push_back(std::move(fn));
}

void Imx31Ccm::RegisterGateListener(std::function<void()> fn) {
    gate_listeners_.push_back(std::move(fn));
}

void Imx31Ccm::NotifyGates() {
    for (auto& fn : gate_listeners_) fn();
}

uint64_t Imx31Ccm::CkilHz() const { return input_->CkilHz(); }

/* Table 3-4: MDS=1 takes the reference clock as the MCU domain source; MPE=0
   switches that source to pll_ref_clk. */
uint64_t Imx31Ccm::McuMainClkHz() const {
    if ((regs_[kCcmrSlot] & kCcmrMds) != 0u) return plls_->RefHz();
    return plls_->OutputHz(0u, plls_->RefHz());
}

/* Figure 3-24: the hsp divider is fed from mcu_main_clk; Table 3-5 HSP_PODF
   [13:11], value + 1. */
uint64_t Imx31Ccm::HspClkHz() const {
    return DividedHz(McuMainClkHz(), ((regs_[kPdr0Slot] >> 11) & 0x7u) + 1u, "hsp_clk");
}

/* Figure 3-24: the ipg divider is fed from hclk; Table 3-5: MAX_PODF [5:3] divides
   mcu_main_clk into hclk and IPG_PODF [7:6] divides hclk, both value + 1. */
uint64_t Imx31Ccm::IpgClkHz() const {
    const uint32_t pdr0 = regs_[kPdr0Slot];
    const uint64_t max_podf = ((pdr0 >> 3) & 0x7u) + 1u;
    const uint64_t ipg_podf = ((pdr0 >> 6) & 0x3u) + 1u;
    return DividedHz(DividedHz(McuMainClkHz(), max_podf, "hclk"), ipg_podf, "ipg_clk");
}

/* MCIMX31RM 3.4.4.3.7: ipg_per_baud is ipg_clk or the USB PLL output through the
   PER_PODF post-divider (Table 3-5 [20:16], value + 1), chosen by CCMR PERCS. */
uint64_t Imx31Ccm::PerClkHz() const {
    const uint32_t ccmr = regs_[kCcmrSlot];
    if ((ccmr & kCcmrPercs) != 0u) return IpgClkHz();
    return DividedHz(plls_->OutputHz(1u, 0u), ((regs_[kPdr0Slot] >> 16) & 0x1Fu) + 1u,
                     "ipg_per_baud");
}

/* Table 3-12: two CG bits per module, index i at bits [2i+1:2i]. */
uint32_t Imx31Ccm::ClockGate0(uint32_t index) const {
    return (regs_[kCgr0Slot] >> (2u * index)) & 0x3u;
}

uint32_t Imx31Ccm::ClockGate1(uint32_t index) const {
    return (regs_[kCgr1Slot] >> (2u * index)) & 0x3u;
}

uint32_t Imx31Ccm::ClockGate(uint32_t cgr, uint32_t index) const {
    return (regs_[kCgr0Slot + cgr] >> (2u * index)) & 0x3u;
}

/* MCIMX31RM Table 3-12: 01 on in run mode only, 10 on in run and wait modes,
   11 on in all modes except when the PLL clock is off. */
bool Imx31Ccm::ClockGateRunsIn(uint32_t cg, FreescaleLowPowerMode mode) {
    switch (mode) {
        case FreescaleLowPowerMode::kRun:  return cg != 0u;
        case FreescaleLowPowerMode::kWait: return cg == 2u || cg == 3u;
        case FreescaleLowPowerMode::kDoze: return cg == 3u;
        default:                           return false;
    }
}

uint32_t Imx31Ccm::LowPowerModeField() const {
    return (regs_[kCcmrSlot] >> kCcmrLpmShift) & 0x3u;
}

/* MCIMX31RM Table 3-4 CCMR LPM [15:14]: the low power mode entered "when the WFI command is next
   executed by the MCU": 00 wait, 01 doze, 10 state retention, 11 deep sleep. */
FreescaleLowPowerMode Imx31Ccm::WfiMode() const {
    switch (LowPowerModeField()) {
        case kLpmWait:      return FreescaleLowPowerMode::kWait;
        case kLpmDoze:      return FreescaleLowPowerMode::kDoze;
        case kLpmRetention: return FreescaleLowPowerMode::kStateRetention;
        default:            break;
    }
    DieDeepSleep();
}

void Imx31Ccm::OnIdle() const {
    if (LowPowerModeField() == kLpmDeepSleep) DieDeepSleep();
}

/* MCIMX31RM Table 3-30 transition 0, the return to run: "Clear LPM bits."; §3.5.2.3: "LPM bits
   in MCR register are cleared by exiting Doze mode." */
void Imx31Ccm::OnIdleExit() {
    regs_[kCcmrSlot] &= ~kCcmrLpmMask;
}

/* MCIMX31RM §3.5.2.5: in deep sleep the "supply of the ARM platform is shut down"; Table 3-30
   transition 5: "If LPM = DSM release the ARM power gating in the chip, release ARM reset". */
void Imx31Ccm::DieDeepSleep() const {
    emu_.Get<Fatal>().Die("Imx31Ccm: WFI with CCMR 0x%08X LPM 11 (deep sleep); the ARM power-down "
                          "and its reset on wake are not modeled", regs_[kCcmrSlot]);
}

uint32_t Imx31Ccm::SsiClockHz(uint32_t ssi) const {
    const uint32_t ccmr = regs_[kCcmrSlot];
    const uint32_t pdr1 = regs_[kPdr1Slot];

    /* Table 3-4: SSI1S = CCMR[19:18], SSI2S = CCMR[22:21].
       Table 3-6: SSI1_PRE_PODF = PDR1[8:6], SSI1_PODF = PDR1[5:0],
                  SSI2_PRE_PODF = PDR1[17:15], SSI2_PODF = PDR1[14:9].
       Both dividers are stored biased by one. */
    uint32_t sel, pre, post;
    if (ssi == 1u) {
        sel  = (ccmr >> 18) & 0x3u;
        pre  = ((pdr1 >> 6) & 0x7u) + 1u;
        post = ((pdr1 >> 0) & 0x3Fu) + 1u;
    } else {
        sel  = (ccmr >> 21) & 0x3u;
        pre  = ((pdr1 >> 15) & 0x7u) + 1u;
        post = ((pdr1 >> 9) & 0x3Fu) + 1u;
    }

    /* §3.4.4.3.4 / §3.4.4.3.5 (p.3-45): the source is the MCU, USB or serial PLL
       output, then SSIn_PRE_PDF and SSIn_PDF. Table 3-4 UPE [9] / SPE [8] disable the
       USB / serial PLL. */
    uint64_t src;
    switch (sel) {
        case 1: src = plls_->OutputHz(1u, 0u); break;
        case 2: src = plls_->OutputHz(2u, 0u); break;
        default:
            emu_.Get<Fatal>().Die("Imx31Ccm: SSI%u clock source select %u (mcu_clk or reserved) "
                                  "is not modeled", ssi, sel);
    }
    return static_cast<uint32_t>(DividedHz(src, static_cast<uint64_t>(pre) * post, "ssi_clk"));
}

uint32_t Imx31Ccm::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t slot;
    if (!OffsetToSlot(off, &slot)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return regs_[slot];
}

void Imx31Ccm::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t slot;
    if (!OffsetToSlot(off, &slot)) HaltUnsupportedAccess("WriteWord", addr, value);
    if (slot == kLtbr0Slot || slot == kLtbr1Slot) return;
    if (slot == kRcsrSlot) {
        constexpr uint32_t kRcsrRoMask = (0x1Fu << 23) | 0x7u;
        regs_[slot] = (regs_[slot] & kRcsrRoMask) | (value & ~kRcsrRoMask);
        return;
    }
    if (slot == kPmcr0Slot) {
        if ((value & kPmcr0DptenBit) != 0 || (value & kPmcr0DvfenBit) != 0) {
            LOG(SocClkpwr, "[CCM] PMCR0 write 0x%08X enables DPTC/DVFS state "
                        "machine; CERF does not simulate workload counters, "
                        "comparator crossings, or interrupt event generation\n",
                value);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        constexpr uint32_t kLbflBit = 1u << 20;
        const uint32_t preserved = regs_[slot] & kLbflBit & value;
        regs_[slot] = (value & ~kLbflBit) | preserved;
        return;
    }
    const uint32_t old = regs_[slot];
    regs_[slot] = value;
    for (uint32_t p = 0; p < Imx31Plls::kCount; ++p) {
        if (slot == kPllSlots[p]) plls_->OnControlWrite(p, old, value, regs_[kCcmrSlot]);
    }
    if (slot == kCcmrSlot) plls_->OnCcmrWrite(old, value, regs_[kRcsrSlot], PllControls());
    const bool timing = slot == kCcmrSlot || slot == kPdr0Slot || slot == kPdr1Slot ||
                        slot == kMpctlSlot || slot == kUpctlSlot || slot == kSpctlSlot ||
                        slot == kCgr0Slot;
    if (timing && old != value) ApplyRates();
    if (slot == kCgr1Slot && old != value) {
        for (auto& fn : gate1_listeners_) fn();
    }
    if (slot >= kCgr0Slot && slot <= kCgr2Slot && old != value) NotifyGates();
}

void Imx31Ccm::SaveState(StateWriter& w) {
    w.WriteBytes("regs", regs_, sizeof(regs_));
    w.Write<uint32_t>("latched_rest", latched_rest_.load(std::memory_order_acquire));
    plls_->SaveState(w);
}

void Imx31Ccm::RestoreState(StateReader& r) {
    r.ReadBytes("regs", regs_, sizeof(regs_));
    uint32_t rest = 0;
    r.Read("latched_rest", rest);
    latched_rest_.store(rest, std::memory_order_release);
    plls_->RestoreState(r);
}

void Imx31Ccm::PostRestore() {
    plls_->PostRestore();
    ApplyRates();
    NotifyGates();
}

uint8_t Imx31Ccm::ReadByte(uint32_t addr) {
    const uint32_t base  = addr & ~0x3u;
    const uint32_t shift = (addr & 0x3u) * 8u;
    return static_cast<uint8_t>((ReadWord(base) >> shift) & 0xFFu);
}

uint16_t Imx31Ccm::ReadHalf(uint32_t addr) {
    if ((addr & 0x1u) != 0) HaltUnsupportedAccess("ReadHalf-unaligned", addr, 0);
    const uint32_t base  = addr & ~0x3u;
    const uint32_t shift = (addr & 0x2u) * 8u;
    return static_cast<uint16_t>((ReadWord(base) >> shift) & 0xFFFFu);
}

void Imx31Ccm::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t base  = addr & ~0x3u;
    const uint32_t shift = (addr & 0x3u) * 8u;
    const uint32_t old   = ReadWord(base);
    const uint32_t merged = (old & ~(0xFFu << shift)) |
                            (static_cast<uint32_t>(value) << shift);
    WriteWord(base, merged);
}

void Imx31Ccm::WriteHalf(uint32_t addr, uint16_t value) {
    if ((addr & 0x1u) != 0) HaltUnsupportedAccess("WriteHalf-unaligned", addr, value);
    const uint32_t base  = addr & ~0x3u;
    const uint32_t shift = (addr & 0x2u) * 8u;
    const uint32_t old   = ReadWord(base);
    const uint32_t merged = (old & ~(0xFFFFu << shift)) |
                            (static_cast<uint32_t>(value) << shift);
    WriteWord(base, merged);
}

REGISTER_SERVICE(Imx31Ccm);
