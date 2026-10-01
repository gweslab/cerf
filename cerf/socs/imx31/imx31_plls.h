#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"
#include "../oscillator_ticks.h"

#include <array>
#include <cstdint>
#include <functional>
#include <vector>

class Imx31ClockInput;
class StateReader;
class StateWriter;

/* MCIMX31RM §3.2.1.3 PLL Reference Clock Switch Unit; §3.2.2 "three DPLLs ... from the PLL
   reference clock". */
class Imx31Plls : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kCount = 3u;
    using Controls = std::array<uint32_t, kCount>;

    bool ShouldRegister() override;
    void OnReady() override;

    void     Attach(uint32_t ccmr, const Controls& ctl);
    void     Settle(uint32_t ccmr, const Controls& ctl);
    void     OnCcmrWrite(uint32_t old, uint32_t value, uint32_t rcsr, const Controls& ctl);
    void     OnControlWrite(uint32_t pll, uint32_t old, uint32_t value, uint32_t ccmr);
    uint64_t RefHz() const;
    uint64_t OutputHz(uint32_t pll, uint64_t off_hz) const;

    void RegisterChangeListener(std::function<void()> fn);

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    static uint32_t Prcs(uint32_t ccmr);

    uint64_t LockedHz(uint32_t pll) const;

    void StartRelock(uint32_t pll, uint32_t ctl);
    void OnLock(uint32_t pll);
    void OnSwitch();
    void Rearm();
    void Notify();

    GuestCycleClock*                               clock_        = nullptr;
    const Imx31ClockInput*                         input_        = nullptr;
    OscillatorTicks                                ref_{emu_, false};
    OscillatorTicks                                ckil_{emu_, false};
    std::array<GuestCycleClock::Event*, kCount>    lock_events_{};
    GuestCycleClock::Event*                        switch_event_ = nullptr;
    std::vector<std::function<void()>>             listeners_;
    Controls                                       ctl_{};
    Controls                                       lock_ctl_{};
    std::array<uint8_t, kCount>                    on_{};
    std::array<uint8_t, kCount>                    relocking_{};
    std::array<uint64_t, kCount>                   lock_tick_{};
    uint8_t                                        prcs_           = 0u;
    uint8_t                                        switch_prcs_    = 0u;
    uint8_t                                        switch_pending_ = 0u;
    uint64_t                                       switch_tick_    = 0u;
};
