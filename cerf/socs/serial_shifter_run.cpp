#include "serial_shifter_run.h"

#include "../state/state_stream.h"
#include "dma_burst_fifo.h"

#include <algorithm>

void SerialShifterRun::Reset() {
    running_   = false;
    run_start_ = 0u;
    run_loads_ = 0u;
    loads_     = 0u;
    prev_last_ = kNever;
}

void SerialShifterRun::Start(uint64_t first) {
    running_   = true;
    run_start_ = first;
    run_loads_ = 0u;
}

uint64_t SerialShifterRun::Settle(uint64_t tick, uint64_t frame, DmaBurstFifo& fifo) {
    if (!running_) return 0u;
    const uint64_t due = tick >= run_start_ ? (tick - run_start_) / frame + 1u : 0u;
    if (due <= run_loads_) return 0u;
    const uint64_t n      = due - run_loads_;
    const uint64_t empty  = fifo.Take(n);
    const uint64_t loaded = n - empty;
    run_loads_ += loaded;
    loads_     += loaded;
    if (empty != 0u) {
        running_   = false;
        prev_last_ = run_start_ + (run_loads_ - 1u) * frame;
    }
    return loaded;
}

bool SerialShifterRun::Busy(uint64_t tick, uint64_t frame, uint64_t tail) const {
    return (running_ && tick >= run_start_) ||
           (prev_last_ != kNever && tick < prev_last_ + frame + tail);
}

bool SerialShifterRun::NextLoadTick(uint64_t ahead, uint64_t frame, uint64_t& tick) const {
    if (!running_ || ahead == 0u) return false;
    tick = run_start_ + (run_loads_ + ahead - 1u) * frame;
    return true;
}

bool SerialShifterRun::TickOfMoved(const DmaBurstFifo& fifo, uint64_t words, uint64_t frame,
                                   bool& immediate, uint64_t& tick) const {
    uint64_t n = 0;
    if (!fifo.TakesToMove(words, n)) return false;
    immediate = n == 0u;
    return immediate || NextLoadTick(n, frame, tick);
}

uint64_t SerialShifterRun::LoadsBy(uint64_t tick, uint64_t frame) const {
    const uint64_t before = loads_ - run_loads_;
    if (run_loads_ != 0u && tick >= run_start_) {
        return before + std::min(run_loads_, (tick - run_start_) / frame + 1u);
    }
    if (prev_last_ != kNever && tick < prev_last_) return before - 1u;
    return before;
}

bool SerialShifterRun::LoadTick(uint64_t load, uint64_t frame, uint64_t takes_left,
                                uint64_t& tick) const {
    const uint64_t before = loads_ - run_loads_;
    if (load <= before) {
        if (load != before || prev_last_ == kNever) return false;
        tick = prev_last_;
        return true;
    }
    const uint64_t k = load - before - 1u;
    if (k >= run_loads_ && (!running_ || k - run_loads_ + 1u > takes_left)) return false;
    tick = run_start_ + k * frame;
    return true;
}

void SerialShifterRun::Save(StateWriter& w) const {
    w.Write<uint8_t>("run_running", running_ ? 1u : 0u);
    w.Write<uint64_t>("run_start", run_start_);
    w.Write<uint64_t>("run_loads", run_loads_);
    w.Write<uint64_t>("run_total", loads_);
    w.Write<uint64_t>("run_prev_last", prev_last_);
}

void SerialShifterRun::Restore(StateReader& r) {
    uint8_t running = 0;
    r.Read("run_running", running);
    r.Read("run_start", run_start_);
    r.Read("run_loads", run_loads_);
    r.Read("run_total", loads_);
    r.Read("run_prev_last", prev_last_);
    running_ = running != 0u;
}
