#pragma once

#include <cstdint>

class StateReader;
class StateWriter;

class S3C2410IisLrckClock {
public:
    static bool Units(uint64_t rate_num, uint64_t rate_den, uint64_t cpu_hz,
                      uint64_t* step, uint64_t* scale);

    void     Start(uint64_t now, uint64_t rate_num, uint64_t rate_den, uint64_t cpu_hz);
    uint64_t Take(uint64_t now);
    uint64_t CycleOf(uint64_t phases) const;
    bool     Retime(uint64_t rate_num, uint64_t rate_den, uint64_t cpu_hz);
    void     ForgetRestored();
    bool     RightPhase() const { return right_; }

    void Save(StateWriter& w, bool running, uint64_t now) const;
    void Restore(StateReader& r, uint64_t now, uint64_t cpu_hz, uint64_t rate_num,
                 uint64_t rate_den, uint64_t max_phases);

private:
    uint64_t anchor_        = 0;
    uint64_t rem_           = 0;
    uint64_t step_          = 0;
    uint64_t scale_         = 1;
    uint64_t rate_num_      = 0;
    uint64_t rate_den_      = 1;
    uint64_t hz_            = 1;
    bool     right_         = false;
    uint64_t restore_since_ = 0;
    uint64_t restore_rem_   = 0;
    bool     restore_right_ = false;
};
