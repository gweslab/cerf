#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"
#include "../cycle_anchored_counter.h"

#include <cstdint>

class Iop13xxWatchdog;
class StateReader;
class StateWriter;

class Iop13xxTimers : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    static bool IsTimerKey(uint32_t key);
    uint32_t    Read(uint32_t key);
    void        Write(uint32_t key, uint32_t value);

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    struct Channel {
        uint32_t                mode          = 0;
        uint32_t                reload        = 0;
        uint32_t                stopped_count = 0;
        uint64_t                next_terminal = 0;
        uint64_t                last_terminal = 0;
        bool                    has_last      = false;
        bool                    stuck_zero    = false;
        CycleAnchoredCounter    counter;
        GuestCycleClock::Event* event = nullptr;
    };

    static uint64_t Divisor(uint32_t mode);
    static uint64_t CyclesPerTick(uint32_t mode);
    static uint64_t ReloadDelay(uint32_t mode);
    static bool     Running(const Channel& ch);
    bool     InReloadWindow(Channel& ch, uint64_t cycle);
    bool     AtTerminalTick(Channel& ch, uint64_t cycle);
    unsigned Index(const Channel& ch) const;
    uint32_t StatusBit(const Channel& ch) const;
    bool     SetTickRatio(Channel& ch);
    [[noreturn]] void RatioOverflow(const Channel& ch);
    void     StopAtTerminal(Channel& ch);
    void     Load(Channel& ch, uint64_t tick, uint32_t count);
    bool     Advance(Channel& ch, uint64_t cycle);
    uint32_t CountAt(Channel& ch, uint64_t cycle);
    void     Arm(Channel& ch);
    uint32_t ReadMode(Channel& ch, uint64_t cycle);
    void     WriteMode(Channel& ch, uint32_t value, uint64_t cycle);
    void     WriteCount(Channel& ch, uint32_t value, uint64_t cycle);
    void     WriteReload(Channel& ch, uint32_t value, uint64_t cycle);
    void     AdvanceAll(uint64_t cycle);
    void     OnChannelEvent(Channel& ch);
    void     ResetState();
    void     PublishLevels();
    void     SaveChannel(StateWriter& w, Channel& ch, uint64_t cycle);
    void     RestoreChannel(StateReader& r, Channel& ch, uint64_t cycle);

    GuestCycleClock* clock_    = nullptr;
    Iop13xxWatchdog* watchdog_ = nullptr;
    Channel          timer_[2];
    uint32_t         tisr_      = 0;
    uint32_t         published_ = 0;
};
