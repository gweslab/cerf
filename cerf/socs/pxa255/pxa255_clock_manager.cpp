#include "pxa255_clock_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "pxa255_id.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

namespace {

constexpr uint64_t kCrystalHz = 3686400u;

/* PXA255 Dev Man Table 3-1, core PLL output frequencies for a 3.6864 MHz
   crystal: "These are the only supported frequency settings." */
struct CorePoint {
    uint32_t l_code;
    uint32_t m_code;
    uint32_t turbo_n_codes;
};
constexpr CorePoint kCorePoints[] = {
    {1u, 1u, (1u << 2) | (1u << 4) | (1u << 6)},
    {3u, 1u, (1u << 2)},
    {1u, 2u, (1u << 2) | (1u << 3) | (1u << 4)},
    {3u, 2u, (1u << 2)},
    {5u, 2u, (1u << 2)},
    {1u, 3u, (1u << 2)},
};

/* Table 3-20: L 00001 = 27, 00011 = 36, 00101 = 45; M 11 "Run mode frequency
   is 4 times the memory frequency" (Table 3-1 row "27 4"); N 010 = 1, 011 = 1.5,
   100 = 2, 110 = 3. */
uint64_t LMultiplier(uint32_t l) { return l == 1u ? 27u : (l == 3u ? 36u : 45u); }
uint64_t MMultiplier(uint32_t m) { return m == 1u ? 1u : (m == 2u ? 2u : 4u); }

uint32_t LCode(uint32_t cccr) { return cccr & 0x1Fu; }
uint32_t MCode(uint32_t cccr) { return (cccr >> 5) & 0x3u; }
uint32_t NCode(uint32_t cccr) { return (cccr >> 7) & 0x7u; }

}  // namespace

bool Pxa255ClockManager::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Pxa255;
}

void Pxa255ClockManager::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    /* §3.6.1 / §3.6.2: CCCR and CKEN are set on hardware and watchdog resets.
       §3.6.3: "OSCC[OOK] can only be reset by a hardware reset." */
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
        /* Table 3-24: TURBO and FCS are "Cleared on hardware, watchdog, and
           GPIO reset and when sleep mode exits." */
        cclkcfg_ = 0u;
        /* §3.4.9.5 step 4: "The processor's PLL clock generator is
           reprogrammed with the values in the CCCR and stabilizes." */
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) {
            LoadPll("sleep exit");
            return;
        }
        if (kind == ResetLineKind::Other) return;
        cccr_        = kCccrReset;
        loaded_cccr_ = kCccrReset;
        cken_        = kCkenReset;
        if (kind == ResetLineKind::Rtc) {
            oon_ = false;
            ook_ = false;
        }
    });
    emu_.Get<GuestCpuReset>().RegisterResetReleaseListener([this] {
        ApplyRate();
        for (auto& fn : osc_listeners_) fn();
    });
    ApplyRate();
}

void Pxa255ClockManager::RegisterOscillatorListener(std::function<void()> fn) {
    osc_listeners_.push_back(std::move(fn));
}

void Pxa255ClockManager::RegisterMemoryClockListener(std::function<void()> fn) {
    memory_clock_listeners_.push_back(std::move(fn));
}

void Pxa255ClockManager::SetOscillatorStable() {
    const bool was_ok = ook_;
    oon_ = true;
    ook_ = true;
    if (!was_ok) {
        for (auto& fn : osc_listeners_) fn();
    }
}

bool Pxa255ClockManager::Supported(uint32_t cccr, bool turbo) const {
    const uint32_t n = NCode(cccr);
    if (n != 2u && n != 3u && n != 4u && n != 6u) return false;
    for (const CorePoint& p : kCorePoints) {
        if (p.l_code != LCode(cccr) || p.m_code != MCode(cccr)) continue;
        return !turbo || (p.turbo_n_codes & (1u << n)) != 0u;
    }
    return false;
}

uint64_t Pxa255ClockManager::MemoryHz(uint32_t cccr) const {
    return kCrystalHz * LMultiplier(LCode(cccr));
}

/* §3.6.1: "Run mode frequency = Memory frequency * ... (M)", "Turbo mode
   frequency = run mode frequency * ... (N)"; the N code counts halves. */
uint64_t Pxa255ClockManager::CoreHz(uint32_t cccr, bool turbo) const {
    const uint64_t run = MemoryHz(cccr) * MMultiplier(MCode(cccr));
    return turbo ? run * NCode(cccr) / 2u : run;
}

void Pxa255ClockManager::LoadPll(const char* when) {
    if (!Supported(cccr_, false)) {
        emu_.Get<Fatal>().Die("Pxa255ClockManager: %s loads CCCR 0x%08X, not a Table 3-1 core "
                              "PLL setting", when, cccr_);
    }
    loaded_cccr_ = cccr_;
    LOG(SocClkpwr, "Pxa255ClockManager: %s loads CCCR 0x%03X\n", when, loaded_cccr_);
}

/* §3.7.1 Table 3-24: FCS "Enter frequency change sequence", TURBO "Enter turbo
   mode"; "Write zeros to reserved bits." §3.4.7.4 step 4: "The FCS bit is not
   automatically cleared." */
void Pxa255ClockManager::WriteClkcfg(uint32_t value) {
    if ((value & ~kClkcfgMask) != 0u) {
        emu_.Get<Fatal>().Die("Pxa255ClockManager: CCLKCFG write 0x%08X sets reserved bits",
                              value);
    }
    if ((value & kClkcfgFcs) != 0u) LoadPll("the frequency change sequence");
    const bool turbo = (value & kClkcfgTurbo) != 0u;
    if (!Supported(loaded_cccr_, turbo)) {
        emu_.Get<Fatal>().Die("Pxa255ClockManager: CCLKCFG write 0x%08X with loaded CCCR 0x%03X "
                              "is not a Table 3-1 core frequency", value, loaded_cccr_);
    }
    cclkcfg_ = value;
    ApplyRate();
}

void Pxa255ClockManager::ApplyRate() {
    emu_.Get<GuestCycleClock>().SetClockHz(
        CoreHz(loaded_cccr_, (cclkcfg_ & kClkcfgTurbo) != 0u));
    if (MemoryClockHz() == published_memory_hz_) return;
    published_memory_hz_ = MemoryClockHz();
    for (auto& fn : memory_clock_listeners_) fn();
}

uint32_t __fastcall Pxa255ClockManager::ReadClkcfgHelper(Pxa255ClockManager* self) {
    return self->cclkcfg_;
}

void __fastcall Pxa255ClockManager::WriteClkcfgHelper(Pxa255ClockManager* self, uint32_t value) {
    self->WriteClkcfg(value);
}

uint32_t Pxa255ClockManager::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
        case 0x00: return cccr_;
        case 0x04: return cken_;
        case 0x08: return (oon_ ? kOsccOon : 0u) | (ook_ ? kOsccOok : 0u);
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255ClockManager::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        case 0x00: cccr_ = value & kCccrMask; return;
        case 0x04: cken_ = value & kCkenMask; return;
        /* Table 3-22: "Write zeros to reserved bits"; OON "write-once only bit",
           OOK "read-only bit". EMTS 278805-002 Table 13: tS_XT Stabilization Time
           min 2, max 10 s. */
        case 0x08:
            if ((value & ~(kOsccOon | kOsccOok)) != 0u) {
                emu_.Get<Fatal>().Die("Pxa255ClockManager: OSCC write 0x%08X sets reserved bits",
                                      value);
            }
            if ((value & kOsccOon) != 0u && !oon_) {
                emu_.Get<Fatal>().Die("Pxa255ClockManager: OSCC write 0x%08X sets OON at run time; "
                                      "the 2-10 s OOK stabilization is not modelled", value);
            }
            return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa255ClockManager::SaveState(StateWriter& w) {
    w.Write("cccr", cccr_); w.Write("cken", cken_); w.Write("oon", oon_); w.Write("ook", ook_);
    w.Write("loaded_cccr", loaded_cccr_); w.Write("cclkcfg", cclkcfg_);
}

void Pxa255ClockManager::RestoreState(StateReader& r) {
    r.Read("cccr", cccr_); r.Read("cken", cken_); r.Read("oon", oon_); r.Read("ook", ook_);
    r.Read("loaded_cccr", loaded_cccr_); r.Read("cclkcfg", cclkcfg_);
    if (ook_ && !oon_) r.Reject("Pxa255ClockManager: OSCC has OOK without OON");
    if ((cccr_ & ~kCccrMask) != 0u || (cken_ & ~kCkenMask) != 0u) {
        r.Reject("Pxa255ClockManager: restored CCCR 0x%08X or CKEN 0x%08X sets a bit the "
                 "register write clears", cccr_, cken_);
    }
    if ((cclkcfg_ & ~kClkcfgMask) != 0u ||
        !Supported(loaded_cccr_, (cclkcfg_ & kClkcfgTurbo) != 0u)) {
        r.Reject("Pxa255ClockManager: loaded CCCR 0x%08X with CCLKCFG 0x%08X is not a "
                 "supported core frequency", loaded_cccr_, cclkcfg_);
    }
}

REGISTER_SERVICE(Pxa255ClockManager);
