#pragma once

#include "../../socs/cycle_anchored_counter.h"

#include <cstdint>
#include <functional>

class CerfEmulator;
class GuestCycleClock;
class StateReader;
class StateWriter;

class Sa1111SerialTransfer {
public:
    struct Keys {
        const char* busy;
        const char* ticks;
        const char* elapsed;
        const char* phase;
        const char* phase_den;
    };
    static constexpr Keys kDefaultKeys = {"xfer_busy", "xfer_ticks", "xfer_elapsed",
                                          "xfer_phase", "xfer_phase_den"};

    Sa1111SerialTransfer(CerfEmulator& emu, const char* owner, uint64_t tick_hz,
                         const Keys& keys = kDefaultKeys,
                         std::function<void(uint64_t now)> settle = {});

    void Attach();
    void Start(uint64_t now, uint64_t ticks);
    void Clear() { active_ = false; }
    void Extend(uint64_t ticks) { ticks_ += ticks; }

    bool Busy(uint64_t now) const { return active_ && Elapsed(now) < ticks_; }
    bool Finished(uint64_t now) const { return active_ && Elapsed(now) >= ticks_; }

    void Save(StateWriter& w, uint64_t now) const;
    void Restore(StateReader& r, uint64_t now);

private:
    uint64_t Elapsed(uint64_t now) const {
        return counter_.AnchorCount() + counter_.TicksSince(now);
    }
    GuestCycleClock& Clock() const;
    void RequireScale(bool fits) const;
    void OnRateChange();

    CerfEmulator&                      emu_;
    const char*                        owner_;
    uint64_t                           tick_hz_;
    Keys                               keys_;
    std::function<void(uint64_t now)>  settle_;
    GuestCycleClock*                   clock_ = nullptr;
    CycleAnchoredCounter               counter_;
    uint64_t                           ticks_  = 0;
    bool                               active_ = false;
};
