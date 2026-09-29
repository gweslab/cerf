#pragma once

#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_base.h"
#include "../cycle_anchored_counter.h"
#include "../oscillator_ticks.h"

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <vector>

class Pr31x00Clock;
class Pr31x00Intc;

/* Philips PR31x00 Timer Module, TMPR3911/3912 ch.15. Registers $140-$157: the
   40-bit RTC counter, the 40-bit Alarm, Timer Control and the Periodic Timer. */
class Pr31x00Rtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x10C00140u; }
    uint32_t MmioSize() const override { return 0x18u; }   /* $140-$157 */

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    uint8_t  ReadByte(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 RTC ReadByte", addr, 0); }
    uint16_t ReadHalf(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 RTC ReadHalf", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("PR31x00 RTC WriteByte", addr, v); }
    void WriteHalf(uint32_t addr, uint16_t v) override { HaltUnsupportedAccess("PR31x00 RTC WriteHalf", addr, v); }

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    uint64_t                Count();
    uint64_t                Tc0Carries();
    std::optional<uint64_t> CycleOfTc0Carry(uint64_t n);
    void                    RegisterCountListener(std::function<void()> fn);

private:
    uint64_t CountAtTickLocked(uint64_t tick) const;
    uint64_t Tc0CarriesAtTickLocked(uint64_t tick) const;
    uint64_t NextRiseTickLocked(uint64_t tick, uint64_t value) const;
    uint32_t RtcRisesLocked(uint64_t from, uint64_t to) const;
    void     RtcEvaluateLocked();
    void     RtcArmLocked();
    void     SetAlarmLocked(uint64_t alarm);
    void     SetRtcClrLocked(bool clr);
    int64_t  RtcWakeDueNs();
    void     NotifyCountListeners();

    void     ApplyTimerCtlLocked(uint32_t value);
    uint64_t PerElapsedLocked();
    uint32_t PerCntLocked();
    void     PerEvaluateLocked();
    void     PerArmLocked();
    void     PerRetimeLocked();
    void     SetPerRatio();

    mutable std::mutex mtx_;

    bool              rtc_clr_    = false;   /* RTCCLR holds the counter at zero */

    uint64_t alarm_          = 0;
    bool     alarm_armed_    = false;   /* ARARM resets to X; live once written */
    uint32_t timer_ctl_      = 0;

    uint16_t perval_           = 0;
    bool     periodic_enabled_ = false;
    bool     per_running_      = false;
    uint64_t per_held_         = 0;
    uint32_t per_loaded_       = 0;
    bool     per_int_done_     = false;

    OscillatorTicks         osc_{emu_, true};
    uint64_t                count_base_  = 0;
    uint64_t                carries_base_ = 0;
    uint64_t                anchor_tick_ = 0;
    uint64_t                seen_tick_   = 0;
    uint32_t                rises_pending_ = 0;
    GuestCycleClock::Event* rtc_event_   = nullptr;
    std::vector<std::function<void()>> count_listeners_;

    CycleAnchoredCounter    per_ctr_;
    GuestCycleClock*        cycle_clock_  = nullptr;
    GuestCycleClock::Event* per_event_    = nullptr;
    Pr31x00Clock*           module_clock_ = nullptr;
    Pr31x00Intc*            intc_         = nullptr;
};
