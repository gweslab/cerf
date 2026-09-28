#include "pxa27x_power_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "pxa270_id.h"
#include "pxa27x_gpio.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 3-38 (page 3-104) "Power
   Manager Register Summary": 0x40F0_0000..0x40F0_00FC. */
enum : uint32_t {
    kPMCR  = 0x00, kPSSR  = 0x04, kPSPR = 0x08, kPWER = 0x0C,
    kPRER  = 0x10, kPFER  = 0x14, kPEDR = 0x18, kPCFR = 0x1C,
    kPGSR0 = 0x20, kPGSR3 = 0x2C, kRCSR = 0x30, kPSLR = 0x34,
    kPSTR  = 0x38, kPVCR  = 0x40, kPUCR = 0x4C, kPKWR = 0x50,
    kPKSR  = 0x54, kPCMD0 = 0x80, kPCMD31 = 0xFC,
};

constexpr uint32_t kPmcrStatus = (1u << 5) | (1u << 3) | (1u << 1);
constexpr uint32_t kPssrW1C    = 0x7Fu;
constexpr uint32_t kRcsrW1C    = 0xFu;
constexpr uint32_t kPksrW1C    = 0xFFFFFu;

constexpr uint32_t kPssrSss   = 1u << 0;
constexpr uint32_t kPssrPh    = 1u << 4;
constexpr uint32_t kPssrRdh   = 1u << 5;
constexpr uint32_t kPssrOtgph = 1u << 6;
constexpr uint32_t kPssrReset = kPssrRdh;

constexpr uint32_t kPcfrPi2cEn = 1u << 6;
constexpr uint32_t kPcfrFvc    = 1u << 10;
constexpr uint32_t kPcfrGprod  = 1u << 12;
constexpr uint32_t kPcfrPo     = 1u << 14;

constexpr uint32_t kPslrSlPi   = 3u << 2;
constexpr uint32_t kPslrReset  = 0xCC000000u;

/* Table 3-17 PWER: WERTC 31; WE15-WE9, WE4, WE3, WE1, WE0 are GPIO edge
   wake enables; reset WE1:0 = 1. */
constexpr uint32_t kPwerRtc   = 1u << 31;
constexpr uint32_t kWakeGpios = 0x0000FE1Bu;
constexpr uint32_t kWakeReset = 0x00000003u;

constexpr uint32_t kRcsrHwr = 1u << 0;
constexpr uint32_t kRcsrWdr = 1u << 1;
constexpr uint32_t kRcsrSmr = 1u << 2;
constexpr uint32_t kRcsrGpr = 1u << 3;

}  // namespace

bool Pxa27xPowerManager::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Pxa270;
}

void Pxa27xPowerManager::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    auto& reset = emu_.Get<GuestCpuReset>();
    reset.SetCauseLatch(this);
    reset.RegisterResetListener([this](ResetLineKind kind) { OnResetLine(kind); });
    reset.RegisterResetReleaseListener([this] { OnSleepExitRelease(); });
    auto& sleep = emu_.Get<GuestDeepSleep>();
    sleep.RegisterWaker(this);
    sleep.RegisterSleepEntryListener([this] { OnSleepEntry(); });
    sleep.RegisterParkWakeSource([this] {
        return wake_edges_.load(std::memory_order_acquire) != 0u;
    });
    emu_.Get<Pxa27xGpio>().SetWakeSink(this);
}

/* §3.8.1.10: "Each RCSR status bit is set by its specific source of reset";
   Table 3-23 SMR 2 "Sleep-Exit Reset from Sleep or Deep-Sleep Mode". */
void Pxa27xPowerManager::LatchSleepWakeCause() {
    rcsr_.fetch_or(kRcsrSmr, std::memory_order_acq_rel);
}

void Pxa27xPowerManager::ClearSleepWakeCause() {
    rcsr_.fetch_and(~kRcsrSmr, std::memory_order_acq_rel);
}

void Pxa27xPowerManager::LatchWarmReset() {
    rcsr_.fetch_or(kRcsrGpr, std::memory_order_acq_rel);
}

void Pxa27xPowerManager::LatchColdReset() {
    rcsr_.fetch_or(kRcsrHwr, std::memory_order_acq_rel);
}

void Pxa27xPowerManager::LatchWatchdogReset() {
    rcsr_.fetch_or(kRcsrWdr, std::memory_order_acq_rel);
}

/* §3.8.1.4: "For a GPIO to serve as a wake-up source ... It must be programmed
   as an input ... Either or both of the corresponding bits in PRER and PFER
   must be set." */
void Pxa27xPowerManager::OnInputEdges(uint32_t rose, uint32_t fell) {
    if (!asleep_.load(std::memory_order_acquire)) return;
    const uint32_t hits = ((rose & prer_.load(std::memory_order_acquire)) |
                           (fell & pfer_.load(std::memory_order_acquire))) &
                          pwer_.load(std::memory_order_acquire) & kWakeGpios;
    if (hits == 0u) return;
    pedr_.fetch_or(hits, std::memory_order_acq_rel);
    wake_edges_.fetch_or(hits, std::memory_order_acq_rel);
}

bool Pxa27xPowerManager::RtcWakeEnabled() const {
    return (pwer_.load(std::memory_order_acquire) & kPwerRtc) != 0u;
}

/* Table 3-20 PEDR: "31 EDRTC ... 1 = Wake-up due to RTC source is detected." */
void Pxa27xPowerManager::LatchRtcWakeEdge() {
    pedr_.fetch_or(kPwerRtc, std::memory_order_acq_rel);
}

/* Table 3-21 PCFR bit 10 FVC: "controls initiation of the voltage-change
   sequence during a frequency change". */
bool Pxa27xPowerManager::FrequencyVoltageChange() const {
    return (pcfr_ & kPcfrFvc) != 0u;
}

void Pxa27xPowerManager::OnSleepEntry() {
    const uint32_t pwer = pwer_.load(std::memory_order_acquire);
    if ((pwer & ~(kWakeGpios | kPwerRtc)) != 0u || pkwr_ != 0u) {
        emu_.Get<Fatal>().Die("Pxa27xPowerManager: sleep entered with PWER 0x%08X PKWR 0x%08X; "
                              "only the GPIO<15:9,4,3,1:0> edge and RTC wake sources are modelled",
                              pwer, pkwr_);
    }
    emu_.Get<Pxa27xGpio>().LoadSleepOutputs(pgsr_, 4u);
    pssr_ |= kPssrSss | kPssrRdh | kPssrOtgph;
    if ((pcfr_ & kPcfrPo) == 0u) pssr_ |= kPssrPh;
    wake_edges_.store(0u, std::memory_order_release);
    asleep_.store(true, std::memory_order_release);
}

/* Table 3-2 (page 3-12), sleep-exit column: PGSR0-3 reset; PVCR and PCMD
   reset unless the pwr_I2C island retains state. Table 3-26 / 3-30: sleep
   exit does not clear them "if the PI power domain is not powered off". */
void Pxa27xPowerManager::ResetForSleepExit() {
    for (uint32_t& v : pgsr_) v = 0u;
    const bool island = (pcfr_ & kPcfrPi2cEn) != 0u;
    const bool pi_on  = (pslr_ & kPslrSlPi) != 0u;
    if (island && pi_on) return;
    bool loaded = pvcr_ != 0u;
    for (uint32_t v : pcmd_) loaded = loaded || v != 0u;
    if (island != pi_on && loaded) {
        emu_.Get<Fatal>().Die("Pxa27xPowerManager: sleep exit with PVCR 0x%08X, PCFR 0x%08X, "
                              "PSLR 0x%08X; PVCR/PCMD retention is not modelled for this mix",
                              pvcr_, pcfr_, pslr_);
    }
    pvcr_ = 0u;
    for (uint32_t& v : pcmd_) v = 0u;
}

/* Table 3-2 (page 3-12): the power manager registers take their reset
   values on GPIO, watchdog and hardware resets; PCFR[GP_ROD] only on
   watchdog and hardware resets. */
void Pxa27xPowerManager::ResetAll(bool keep_gprod) {
    pmcr_ = 0u;
    pssr_ = kPssrReset;
    pspr_ = 0u;
    pcfr_ = keep_gprod ? (pcfr_ & kPcfrGprod) : 0u;
    pslr_ = kPslrReset;
    pstr_ = 0u;
    pvcr_ = 0u;
    pucr_ = 0u;
    pkwr_ = 0u;
    pksr_ = 0u;
    for (uint32_t& v : pgsr_) v = 0u;
    for (uint32_t& v : pcmd_) v = 0u;
    pwer_.store(kWakeReset, std::memory_order_release);
    prer_.store(kWakeReset, std::memory_order_release);
    pfer_.store(kWakeReset, std::memory_order_release);
    pedr_.store(0u, std::memory_order_release);
}

void Pxa27xPowerManager::OnResetLine(ResetLineKind kind) {
    asleep_.store(false, std::memory_order_release);
    wake_edges_.store(0u, std::memory_order_release);
    if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) {
        ResetForSleepExit();
        return;
    }
    ResetAll(kind == ResetLineKind::Other);
}

/* Table 3-21 PCFR PO: "1 = PSSR[PH] is automatically cleared after exiting the
   low-power mode." */
void Pxa27xPowerManager::OnSleepExitRelease() {
    if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
    if ((pcfr_ & kPcfrPo) != 0u) WritePssr(kPssrPh);
}

void Pxa27xPowerManager::WritePssr(uint32_t value) {
    const bool held = (pssr_ & kPssrPh) != 0u;
    pssr_ &= ~(value & kPssrW1C);
    if (held && (pssr_ & kPssrPh) == 0u) emu_.Get<Pxa27xGpio>().ReleaseSleepHold();
}

uint32_t Pxa27xPowerManager::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off >= kPCMD0 && off <= kPCMD31) return pcmd_[(off - kPCMD0) / 4];
    if (off >= kPGSR0 && off <= kPGSR3)  return pgsr_[(off - kPGSR0) / 4];
    switch (off) {
    case kPMCR: return pmcr_;
    case kPSSR: return pssr_;
    case kPSPR: return pspr_;
    case kPWER: return pwer_.load(std::memory_order_acquire);
    case kPRER: return prer_.load(std::memory_order_acquire);
    case kPFER: return pfer_.load(std::memory_order_acquire);
    case kPEDR: return pedr_.load(std::memory_order_acquire);
    case kPCFR: return pcfr_;
    case kRCSR: return rcsr_.load(std::memory_order_acquire);
    case kPSLR: return pslr_;
    case kPSTR: return pstr_;
    case kPVCR: return pvcr_;
    case kPUCR: return pucr_;
    case kPKWR: return pkwr_;
    case kPKSR: return pksr_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa27xPowerManager::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off >= kPCMD0 && off <= kPCMD31) {
        pcmd_[(off - kPCMD0) / 4] = value;
        return;
    }
    if (off >= kPGSR0 && off <= kPGSR3) {
        pgsr_[(off - kPGSR0) / 4] = value;
        return;
    }
    switch (off) {
    case kPSPR: pspr_ = value; return;
    case kPWER: pwer_.store(value, std::memory_order_release); return;
    case kPRER: prer_.store(value, std::memory_order_release); return;
    case kPFER: pfer_.store(value, std::memory_order_release); return;
    case kPCFR: pcfr_ = value; return;
    case kPSLR: pslr_ = value; return;
    case kPSTR: pstr_ = value; return;
    case kPVCR: pvcr_ = value; return;
    case kPUCR: pucr_ = value; return;
    case kPKWR: pkwr_ = value; return;
    case kPMCR:
        pmcr_ = (pmcr_ & kPmcrStatus & ~value) | (value & ~kPmcrStatus);
        return;
    case kPSSR: WritePssr(value); return;
    case kPEDR: pedr_.fetch_and(~value, std::memory_order_acq_rel);             return;
    case kRCSR: rcsr_.fetch_and(~(value & kRcsrW1C), std::memory_order_acq_rel); return;
    case kPKSR: pksr_ &= ~(value & kPksrW1C);                                   return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa27xPowerManager::SaveState(StateWriter& w) {
    w.Write("pmcr", pmcr_); w.Write("pssr", pssr_); w.Write("pspr", pspr_);
    w.Write("pwer", pwer_.load(std::memory_order_acquire));
    w.Write("prer", prer_.load(std::memory_order_acquire));
    w.Write("pfer", pfer_.load(std::memory_order_acquire));
    w.Write("pedr", pedr_.load(std::memory_order_acquire));
    w.Write("pcfr", pcfr_);
    w.Write("rcsr", rcsr_.load(std::memory_order_acquire));
    w.Write("pslr", pslr_); w.Write("pstr", pstr_); w.Write("pvcr", pvcr_);
    w.Write("pucr", pucr_); w.Write("pkwr", pkwr_); w.Write("pksr", pksr_);
    for (uint32_t& v : pgsr_) w.Write("pgsr", v);
    for (uint32_t& v : pcmd_) w.Write("pcmd", v);
    w.Write("wake_edges", wake_edges_.load(std::memory_order_acquire));
    w.Write<uint8_t>("asleep", asleep_.load(std::memory_order_acquire) ? 1u : 0u);
}

void Pxa27xPowerManager::RestoreState(StateReader& r) {
    uint32_t pwer = 0, prer = 0, pfer = 0, pedr = 0, rcsr = 0, edges = 0;
    uint8_t  asleep = 0;
    r.Read("pmcr", pmcr_); r.Read("pssr", pssr_); r.Read("pspr", pspr_);
    r.Read("pwer", pwer);  r.Read("prer", prer);  r.Read("pfer", pfer);
    r.Read("pedr", pedr);  r.Read("pcfr", pcfr_);
    r.Read("rcsr", rcsr);
    r.Read("pslr", pslr_); r.Read("pstr", pstr_); r.Read("pvcr", pvcr_);
    r.Read("pucr", pucr_); r.Read("pkwr", pkwr_); r.Read("pksr", pksr_);
    for (uint32_t& v : pgsr_) r.Read("pgsr", v);
    for (uint32_t& v : pcmd_) r.Read("pcmd", v);
    r.Read("wake_edges", edges);
    r.Read("asleep", asleep);
    if ((edges & ~kWakeGpios) != 0u || asleep > 1u) {
        r.Reject("Pxa27xPowerManager: wake edge latch 0x%08X or sleep flag %u out of range",
                 edges, asleep);
    }
    if ((rcsr & ~(kRcsrHwr | kRcsrWdr | kRcsrSmr | kRcsrGpr)) != 0u ||
        (pssr_ & ~(kPssrSss | kPssrPh | kPssrRdh | kPssrOtgph)) != 0u ||
        (pedr & ~(kWakeGpios | kPwerRtc)) != 0u || pksr_ != 0u) {
        r.Reject("Pxa27xPowerManager: restored RCSR 0x%08X, PSSR 0x%08X, PEDR 0x%08X or PKSR "
                 "0x%08X holds a bit no reset, sleep or wake sets", rcsr, pssr_, pedr, pksr_);
    }
    pwer_.store(pwer, std::memory_order_release);
    prer_.store(prer, std::memory_order_release);
    pfer_.store(pfer, std::memory_order_release);
    pedr_.store(pedr, std::memory_order_release);
    rcsr_.store(rcsr, std::memory_order_release);
    wake_edges_.store(edges, std::memory_order_release);
    asleep_.store(asleep != 0u, std::memory_order_release);
}

REGISTER_SERVICE(Pxa27xPowerManager);
