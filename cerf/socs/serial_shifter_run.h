#pragma once

#include <cstdint>

class DmaBurstFifo;
class StateReader;
class StateWriter;

class SerialShifterRun {
public:
    static constexpr uint64_t kNever = UINT64_MAX;

    void     Reset();
    void     Start(uint64_t first);
    uint64_t Settle(uint64_t tick, uint64_t frame, DmaBurstFifo& fifo);

    bool     Running() const { return running_; }
    uint64_t RunStart() const { return run_start_; }
    uint64_t RunLoads() const { return run_loads_; }
    bool     Busy(uint64_t tick, uint64_t frame, uint64_t tail) const;
    bool     NextLoadTick(uint64_t ahead, uint64_t frame, uint64_t& tick) const;
    bool     TickOfMoved(const DmaBurstFifo& fifo, uint64_t words, uint64_t frame,
                         bool& immediate, uint64_t& tick) const;
    uint64_t LoadsBy(uint64_t tick, uint64_t frame) const;
    bool     LoadTick(uint64_t load, uint64_t frame, uint64_t takes_left, uint64_t& tick) const;

    void Save(StateWriter& w) const;
    void Restore(StateReader& r);

private:
    bool     running_   = false;
    uint64_t run_start_ = 0;
    uint64_t run_loads_ = 0;
    uint64_t loads_     = 0;
    uint64_t prev_last_ = kNever;
};
