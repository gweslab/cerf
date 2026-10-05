#include "pxa27x_clock_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "pxa270_id.h"
#include "pxa27x_power_manager.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

/* Intel PXA27x Developer's Manual 280000-001 chapter 3: Table 3-31 (page 3-95)
   "0x4130_0000 CCCR", Table 3-32 (page 3-97) "0x4130_0004 CKEN", Table 3-34
   (page 3-99) "0x4130_0008 OSCC", Table 3-35 (page 3-101) "0x4130_000C CCSR". */

namespace {

constexpr uint32_t kCcsrFromCccr = 0xC000039Fu;

/* Table 3-35 (page 3-101): "29 R CPLCK ... 1 = Core PLL is locked and ready
   to use", "28 R PPLCK ... Peripheral PLL Lock". */
constexpr uint32_t kCcsrLocked = 0x30000000u;

constexpr uint64_t kOscHz = 13000000u;

/* Table 3-7 (page 3-20) "Clock Frequencies": the CCCR[L] / CCCR[2N] pairs of
   the PLL rows, CLKCFG[T] "-" on the L 7 row, and CLKCFG[HT] set only on the
   L 8, 2N 6 row. */
struct CorePoint {
    uint32_t l;
    uint32_t n2;
    bool     turbo;
    bool     half_turbo;
};
constexpr CorePoint kCorePoints[] = {
    {7u, 2u, false, false}, {8u, 2u, true, false},  {8u, 6u, true, true},
    {16u, 2u, true, false}, {16u, 3u, true, false}, {16u, 4u, true, false},
    {16u, 5u, true, false}, {16u, 6u, true, false},
};

uint32_t LField(uint32_t cccr)  { return cccr & 0x1Fu; }
uint32_t N2Field(uint32_t cccr) { return (cccr >> 7) & 0xFu; }

}  // namespace

bool Pxa27xClockManager::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Pxa270;
}

void Pxa27xClockManager::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
        /* §3.8.3: "Power-on, hardware, watchdog, GPIO, sleep, and deep-sleep
           resets clear these registers." */
        clkcfg_ = 0u;
        /* §3.6.9.4 step 6: "The PLLs are restarted with the corresponding
           values in the Core Clock Configuration register". */
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) {
            LoadPll("sleep exit");
            return;
        }
        if (kind == ResetLineKind::Other) return;
        cccr_        = kCccrReset;
        loaded_cccr_ = kCccrReset;
        cken_        = kCkenReset;
        if (kind == ResetLineKind::Rtc) oscc_ = 0u;
    });
    emu_.Get<GuestCpuReset>().RegisterResetReleaseListener([this] {
        ApplyRate();
        FireOscillatorListeners();
    });
    ApplyRate();
}

void Pxa27xClockManager::RegisterOscillatorListener(std::function<void()> fn) {
    osc_listeners_.push_back(std::move(fn));
}

void Pxa27xClockManager::FireOscillatorListeners() {
    for (auto& fn : osc_listeners_) fn();
}

void Pxa27xClockManager::SetOscillatorStable() {
    const bool was_ok = OscillatorOk();
    oscc_ |= kOsccOon | kOsccOok;
    if (!was_ok) FireOscillatorListeners();
}

/* §3.5.7.5: "Half-turbo mode can only be invoked when the CCSR reflects 2*N
   values of 6 or 8." */
bool Pxa27xClockManager::Supported(uint32_t cccr, uint32_t clkcfg) const {
    const bool half  = (clkcfg & kClkcfgHt) != 0u;
    const bool turbo = (clkcfg & kClkcfgT) != 0u;
    for (const CorePoint& p : kCorePoints) {
        if (p.l != LField(cccr) || p.n2 != N2Field(cccr)) continue;
        return (!turbo || p.turbo) && (!half || p.half_turbo);
    }
    return false;
}

/* §3.5.7.4: "CLKCFG[T] set - CPU operates at the turbo frequency"; §3.5.7.5:
   "CLKCFG[HT] set - the CPU operates at the turbo-mode frequency divided by
   two"; Table 3-7: run = 13 MHz x L, turbo = run x 2N / 2. */
uint64_t Pxa27xClockManager::CoreHz(uint32_t cccr, uint32_t clkcfg) const {
    const uint64_t run = kOscHz * LField(cccr);
    if ((clkcfg & kClkcfgHt) != 0u) return run * N2Field(cccr) / 4u;
    if ((clkcfg & kClkcfgT) != 0u)  return run * N2Field(cccr) / 2u;
    return run;
}

void Pxa27xClockManager::LoadPll(const char* when) {
    if (!Supported(cccr_, 0u)) {
        emu_.Get<Fatal>().Die("Pxa27xClockManager: %s loads CCCR 0x%08X, not a Table 3-7 core "
                              "PLL setting", when, cccr_);
    }
    loaded_cccr_ = cccr_;
    LOG(SocClkpwr, "Pxa27xClockManager: %s loads CCCR 0x%08X\n", when, loaded_cccr_);
}

/* §3.8.3.1 Table 3-36: B 3, HT 2, F 1 "Frequency-change sequence begins when
   written", T 0; "Write 0b0 to reserved bits". §3.5.7.3.2: "Do not set
   CLKCFG[HT] while performing a frequency change." */
void Pxa27xClockManager::WriteClkcfg(uint32_t value) {
    if ((value & ~kClkcfgMask) != 0u) {
        emu_.Get<Fatal>().Die("Pxa27xClockManager: CLKCFG write 0x%08X sets reserved bits",
                              value);
    }
    if ((value & kClkcfgF) != 0u) {
        if ((value & kClkcfgHt) != 0u) {
            emu_.Get<Fatal>().Die("Pxa27xClockManager: CLKCFG write 0x%08X sets HT during a "
                                  "frequency change", value);
        }
        LoadPll("the frequency change sequence");
    }
    if (!Supported(loaded_cccr_, value)) {
        emu_.Get<Fatal>().Die("Pxa27xClockManager: CLKCFG write 0x%08X with loaded CCCR "
                              "0x%08X is not a Table 3-7 core frequency", value, loaded_cccr_);
    }
    clkcfg_ = value;
    ApplyRate();
}

/* Section 3.8.2.1 (page 3-94): "LCD frequency = 13-MHz processor-oscillator
   frequency * L / K, where K = 1 (L = 2-7), K = 2 (L = 8-16), or K = 4
   (L = 17-31)"; "a frequency change is required to enact any changes". */
uint64_t Pxa27xClockManager::LcdClockHz() const {
    const uint32_t l = LField(loaded_cccr_);
    const uint32_t k = l <= 7u ? 1u : (l <= 16u ? 2u : 4u);
    return kOscHz * l / k;
}

void Pxa27xClockManager::RegisterLcdClockListener(std::function<void()> fn) {
    lcd_clock_listeners_.push_back(std::move(fn));
}

void Pxa27xClockManager::RegisterClockEnableListener(std::function<void(uint32_t)> fn) {
    cken_listeners_.push_back(std::move(fn));
}

void Pxa27xClockManager::ApplyRate() {
    emu_.Get<GuestCycleClock>().SetClockHz(CoreHz(loaded_cccr_, clkcfg_));
    PublishLcdClock();
}

void Pxa27xClockManager::PublishLcdClock() {
    const uint64_t lcd_hz = LcdClockHz();
    const bool     lcd_on = LcdClockEnabled();
    if (lcd_hz == published_lcd_hz_ && lcd_on == published_lcd_on_) return;
    published_lcd_hz_ = lcd_hz;
    published_lcd_on_ = lcd_on;
    for (auto& fn : lcd_clock_listeners_) fn();
}

uint32_t __fastcall Pxa27xClockManager::ReadClkcfgHelper(Pxa27xClockManager* self) {
    return self->clkcfg_;
}

void __fastcall Pxa27xClockManager::WriteClkcfgHelper(Pxa27xClockManager* self, uint32_t value) {
    if ((value & kClkcfgF) != 0u &&
        self->emu_.Get<Pxa27xPowerManager>().FrequencyVoltageChange()) {
        self->emu_.Get<Fatal>().Die("Pxa27xClockManager: CLKCFG write 0x%08X starts a frequency "
                                    "change with PCFR[FVC] set; the voltage-change sequence is "
                                    "not modelled", value);
    }
    self->WriteClkcfg(value);
}

uint32_t Pxa27xClockManager::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
        case 0x00: return cccr_;
        case 0x04: return cken_;
        case 0x08: return oscc_;
        case 0x0C: return (loaded_cccr_ & kCcsrFromCccr) | kCcsrLocked;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa27xClockManager::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        /* Table 3-31: CPDIS 31, PPDIS 30 turn a PLL off; §3.5.5: "CCCR[CPDIS]
           = 0 and CCCR[PPDIS] = 1" is not supported. */
        case 0x00:
            if ((value & kCccrPllOff) != 0u) {
                emu_.Get<Fatal>().Die("Pxa27xClockManager: CCCR write 0x%08X disables a PLL; "
                                      "the 13-MHz modes are not modelled", value);
            }
            cccr_ = value & kCccrMask;
            return;
        case 0x04: {
            const uint32_t old = cken_;
            cken_ = value & kCkenMask;
            PublishLcdClock();
            if (cken_ == old) return;
            LOG(SocClkpwr, "Pxa27xClockManager: CKEN <= 0x%08X\n", cken_);
            for (auto& fn : cken_listeners_) fn(old);
            return;
        }
        /* Section 3.8.2.3 (page 3-99): "OON can be set only by software and
           cleared only by power-on or hardware reset", and "OOK sets 2-3
           seconds after OON is set". */
        case 0x08:
            if ((value & kOsccOon) != 0u && (oscc_ & kOsccOon) == 0u) {
                emu_.Get<Fatal>().Die("Pxa27xClockManager: OSCC write 0x%08X sets OON at run time; "
                                      "the 2-3 s OOK stabilization is not modelled", value);
            }
            oscc_ = (value & kOsccMask) | (oscc_ & (kOsccOon | kOsccOok));
            return;
        /* Section 3.8.2.4 (page 3-100): "This is a read-only register." */
        case 0x0C: return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa27xClockManager::SaveState(StateWriter& w) {
    w.Write("cccr", cccr_); w.Write("cken", cken_); w.Write("oscc", oscc_);
    w.Write("loaded_cccr", loaded_cccr_); w.Write("clkcfg", clkcfg_);
}

void Pxa27xClockManager::RestoreState(StateReader& r) {
    r.Read("cccr", cccr_); r.Read("cken", cken_); r.Read("oscc", oscc_);
    r.Read("loaded_cccr", loaded_cccr_); r.Read("clkcfg", clkcfg_);
    if ((cccr_ & ~kCccrMask) != 0u || (cccr_ & kCccrPllOff) != 0u || (cken_ & ~kCkenMask) != 0u ||
        (oscc_ & ~(kOsccMask | kOsccOon | kOsccOok)) != 0u) {
        r.Reject("Pxa27xClockManager: restored CCCR 0x%08X, CKEN 0x%08X or OSCC 0x%08X holds a "
                 "value the register write halts on or clears", cccr_, cken_, oscc_);
    }
    if ((oscc_ & kOsccOok) != 0u && (oscc_ & kOsccOon) == 0u) {
        r.Reject("Pxa27xClockManager: OSCC 0x%08X has OOK without OON", oscc_);
    }
    if ((clkcfg_ & ~kClkcfgMask) != 0u || !Supported(loaded_cccr_, clkcfg_)) {
        r.Reject("Pxa27xClockManager: loaded CCCR 0x%08X with CLKCFG 0x%08X is not a "
                 "supported core frequency", loaded_cccr_, clkcfg_);
    }
}

REGISTER_SERVICE(Pxa27xClockManager);
