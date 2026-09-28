#include "pxa255_power_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "pxa255_id.h"
#include "pxa255_gpio.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

namespace {

enum : uint32_t {
    kPMCR  = 0x00, kPSSR  = 0x04, kPSPR  = 0x08, kPWER  = 0x0C,
    kPRER  = 0x10, kPFER  = 0x14, kPEDR  = 0x18, kPCFR  = 0x1C,
    kPGSR0 = 0x20, kPGSR1 = 0x24, kPGSR2 = 0x28, kRCSR  = 0x30,
};

/* Table 3-9 / 3-10 / 3-11: PWER, PRER and PFER "Set to 0x0003 on hardware,
   watchdog, and GPIO resets"; WERTC "Cleared on hardware, watchdog, and GPIO
   resets". */
constexpr uint32_t kWakeReset   = 0x00000003u;
constexpr uint32_t kPwerRtc     = 1u << 31;
constexpr uint32_t kWakeGpios   = 0x0000FFFFu;

/* Table 3-13: SSS [0], PH [4], RDH [5]; RDH "Set by hardware, watchdog, and
   GPIO resets and sleep mode". */
constexpr uint32_t kPssrSss   = 1u << 0;
constexpr uint32_t kPssrPh    = 1u << 4;
constexpr uint32_t kPssrRdh   = 1u << 5;
constexpr uint32_t kPssrReset = kPssrRdh;

/* Table 3-19: HWR [0], WDR [1], SMR [2], GPR [3]. */
constexpr uint32_t kRcsrHwr = 1u << 0;
constexpr uint32_t kRcsrWdr = 1u << 1;
constexpr uint32_t kRcsrSmr = 1u << 2;
constexpr uint32_t kRcsrGpr = 1u << 3;

}  // namespace

bool Pxa255PowerManager::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Pxa255;
}

void Pxa255PowerManager::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    auto& reset = emu_.Get<GuestCpuReset>();
    reset.SetCauseLatch(this);
    reset.RegisterResetListener([this](ResetLineKind kind) { OnResetLine(kind); });
    auto& sleep = emu_.Get<GuestDeepSleep>();
    sleep.RegisterWaker(this);
    sleep.RegisterSleepEntryListener([this] { OnSleepEntry(); });
    sleep.RegisterParkWakeSource([this] {
        return wake_edges_.load(std::memory_order_acquire) != 0u;
    });
    emu_.Get<Pxa255Gpio>().SetWakeSink(this);
}

/* Table 3-19 SMR: "Sleep mode has occurred since the last time the CPU or
   hardware reset cleared this bit." */
void Pxa255PowerManager::LatchSleepWakeCause() {
    rcsr_.fetch_or(kRcsrSmr, std::memory_order_acq_rel);
}

void Pxa255PowerManager::ClearSleepWakeCause() {
    rcsr_.fetch_and(~kRcsrSmr, std::memory_order_acq_rel);
}

/* §3.4.3: in GPIO Reset the Memory Controller keeps its state, the one PXA255
   reset that preserves DRAM. Table 3-19 GPR: "GPIO reset has occurred since the
   last time the CPU or hardware reset cleared this bit." */
void Pxa255PowerManager::LatchWarmReset() {
    rcsr_.fetch_or(kRcsrGpr, std::memory_order_acq_rel);
}

/* Table 3-19: HWR "Set by hardware reset"; GPR, SMR and WDR are "Cleared by
   hardware reset". */
void Pxa255PowerManager::LatchColdReset() {
    rcsr_.store(kRcsrHwr, std::memory_order_release);
}

void Pxa255PowerManager::LatchWatchdogReset() {
    rcsr_.fetch_or(kRcsrWdr, std::memory_order_acq_rel);
}

void Pxa255PowerManager::OnInputEdges(uint32_t rose, uint32_t fell) {
    if (!asleep_.load(std::memory_order_acquire)) return;
    const uint32_t hits = ((rose & prer_.load(std::memory_order_acquire)) |
                           (fell & pfer_.load(std::memory_order_acquire))) &
                          pwer_.load(std::memory_order_acquire) & kWakeGpios;
    LOG(SocReset, "[PWRMGR] pxa255 edge while asleep: rose=0x%08X fell=0x%08X hits=0x%08X\n",
        rose, fell, hits);
    if (hits == 0u) return;
    pedr_.fetch_or(hits, std::memory_order_acq_rel);
    wake_edges_.fetch_or(hits, std::memory_order_acq_rel);
}

bool Pxa255PowerManager::RtcAlarmWakeEnabled() const {
    return (pwer_.load(std::memory_order_acquire) & kPwerRtc) != 0u;
}

/* nec_mobilepro_900_ce4_2 SABOOT.NB0 nk.exe sub_9006AF28: a sleep boot with
   PEDR bit 31 set is the alarm wake ("Battery too low to service alarm").
   PXA27x Dev Man Table 3-20: PEDR bit 31 EDRTC, "Wake-up from RTC". */
void Pxa255PowerManager::LatchRtcWakeEdge() {
    pedr_.fetch_or(kPwerRtc, std::memory_order_acq_rel);
}

/* Table 3-13: SSS is set when "sleep mode starts" through PWRMODE, PH "Set
   when sleep mode starts", RDH set by "sleep mode". */
void Pxa255PowerManager::OnSleepEntry() {
    LOG(SocReset, "[PWRMGR] pxa255 sleep: pwer=0x%08X prer=0x%08X pfer=0x%08X pedr=0x%08X\n",
        pwer_.load(std::memory_order_acquire), prer_.load(std::memory_order_acquire),
        pfer_.load(std::memory_order_acquire), pedr_.load(std::memory_order_acquire));
    const uint32_t pgsr[3] = {pgsr0_, pgsr1_, pgsr2_};
    emu_.Get<Pxa255Gpio>().LoadSleepOutputs(pgsr, 3u);
    pssr_ |= kPssrSss | kPssrPh | kPssrRdh;
    wake_edges_.store(0u, std::memory_order_release);
    asleep_.store(true, std::memory_order_release);
}

/* §3.5.1-§3.5.8, Tables 3-7 to 3-17: PMCR, PCFR, PSPR and PGSR clear, PWER /
   PRER / PFER load 0x3, PEDR clears and PSSR takes RDH on hardware, watchdog
   and GPIO resets. PMCR IDAE is also "Cleared ... when sleep mode exits". */
void Pxa255PowerManager::OnResetLine(ResetLineKind) {
    asleep_.store(false, std::memory_order_release);
    wake_edges_.store(0u, std::memory_order_release);
    pmcr_ = 0u;
    if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
    pcfr_  = 0u;
    pspr_  = 0u;
    pgsr0_ = 0u;
    pgsr1_ = 0u;
    pgsr2_ = 0u;
    pssr_  = kPssrReset;
    pwer_.store(kWakeReset, std::memory_order_release);
    prer_.store(kWakeReset, std::memory_order_release);
    pfer_.store(kWakeReset, std::memory_order_release);
    pedr_.store(0u, std::memory_order_release);
}

uint32_t Pxa255PowerManager::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
    case kPMCR:  return pmcr_;
    case kPSSR:  return pssr_;
    case kPSPR:  return pspr_;
    case kPWER:  return pwer_.load(std::memory_order_acquire);
    case kPRER:  return prer_.load(std::memory_order_acquire);
    case kPFER:  return pfer_.load(std::memory_order_acquire);
    case kPEDR:  return pedr_.load(std::memory_order_acquire);
    case kPCFR:  return pcfr_;
    case kPGSR0: return pgsr0_;
    case kPGSR1: return pgsr1_;
    case kPGSR2: return pgsr2_;
    case kRCSR:  return rcsr_.load(std::memory_order_acquire);
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

/* nec_mobilepro_900_ce4_2 XIP.BIN nk.exe 0x90201000-0x90201004: LDR R0, =0x40F00030 (RCSR),
   LDRB R1, [R0]. */
uint8_t Pxa255PowerManager::ReadByte(uint32_t addr) {
    if (addr != MmioBase() + 0x30u) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>(ReadWord(addr));
}

void Pxa255PowerManager::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
    case kPMCR:  pmcr_  = value; return;
    case kPSPR:  pspr_  = value; return;
    case kPWER:  pwer_.store(value, std::memory_order_release); return;
    case kPRER:  prer_.store(value, std::memory_order_release); return;
    case kPFER:  pfer_.store(value, std::memory_order_release); return;
    case kPCFR:  pcfr_  = value; return;
    case kPGSR0: pgsr0_ = value; return;
    case kPGSR1: pgsr1_ = value; return;
    case kPGSR2: pgsr2_ = value; return;
    case kPSSR: {
        const bool held = (pssr_ & kPssrPh) != 0u;
        pssr_ &= ~value;
        if (held && (pssr_ & kPssrPh) == 0u) emu_.Get<Pxa255Gpio>().ReleaseSleepHold();
        return;
    }
    case kPEDR:  pedr_.fetch_and(~value, std::memory_order_acq_rel); return;
    case kRCSR:  rcsr_.fetch_and(~(value & 0xFu), std::memory_order_acq_rel); return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa255PowerManager::SaveState(StateWriter& w) {
    w.Write("pmcr", pmcr_);  w.Write("pssr", pssr_);  w.Write("pspr", pspr_);
    w.Write("pwer", pwer_.load(std::memory_order_acquire));
    w.Write("prer", prer_.load(std::memory_order_acquire));
    w.Write("pfer", pfer_.load(std::memory_order_acquire));
    w.Write("pedr", pedr_.load(std::memory_order_acquire));
    w.Write("pcfr", pcfr_);
    w.Write("pgsr0", pgsr0_); w.Write("pgsr1", pgsr1_); w.Write("pgsr2", pgsr2_);
    w.Write("rcsr", rcsr_.load(std::memory_order_acquire));
    w.Write("wake_edges", wake_edges_.load(std::memory_order_acquire));
    w.Write<uint8_t>("asleep", asleep_.load(std::memory_order_acquire) ? 1u : 0u);
}

void Pxa255PowerManager::RestoreState(StateReader& r) {
    uint32_t pwer = 0, prer = 0, pfer = 0, pedr = 0, rcsr = 0, edges = 0;
    uint8_t  asleep = 0;
    r.Read("pmcr", pmcr_);  r.Read("pssr", pssr_);  r.Read("pspr", pspr_);
    r.Read("pwer", pwer);   r.Read("prer", prer);   r.Read("pfer", pfer);
    r.Read("pedr", pedr);   r.Read("pcfr", pcfr_);
    r.Read("pgsr0", pgsr0_); r.Read("pgsr1", pgsr1_); r.Read("pgsr2", pgsr2_);
    r.Read("rcsr", rcsr);
    r.Read("wake_edges", edges);
    r.Read("asleep", asleep);
    if ((edges & ~kWakeGpios) != 0u || asleep > 1u) {
        r.Reject("Pxa255PowerManager: wake edge latch 0x%08X or sleep flag %u out of range",
                 edges, asleep);
    }
    if ((rcsr & ~(kRcsrHwr | kRcsrWdr | kRcsrSmr | kRcsrGpr)) != 0u ||
        (pssr_ & ~(kPssrSss | kPssrPh | kPssrRdh)) != 0u ||
        (pedr & ~(kWakeGpios | kPwerRtc)) != 0u) {
        r.Reject("Pxa255PowerManager: restored RCSR 0x%08X, PSSR 0x%08X or PEDR 0x%08X holds a "
                 "bit no reset, sleep or wake sets", rcsr, pssr_, pedr);
    }
    pwer_.store(pwer, std::memory_order_release);
    prer_.store(prer, std::memory_order_release);
    pfer_.store(pfer, std::memory_order_release);
    pedr_.store(pedr, std::memory_order_release);
    rcsr_.store(rcsr, std::memory_order_release);
    wake_edges_.store(edges, std::memory_order_release);
    asleep_.store(asleep != 0u, std::memory_order_release);
}

REGISTER_SERVICE(Pxa255PowerManager);
