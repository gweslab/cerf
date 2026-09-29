#pragma once

#include "vr41xx_rtcl_census.h"

#include <cstdint>
#include <optional>

class StateReader;
class StateWriter;

struct Vr41xxRtclView {
    uint32_t reload  = 0;
    uint64_t anchor  = 0;
    uint64_t periods = 0;
    uint64_t ack       = 0;
    bool     latched   = false;
    bool     pair_open = false;
};

class Vr41xxRtclRephase {
public:
    static constexpr int kTickChannel = 0;

    void OnPairStart(int ch, bool repeat_half, uint64_t now, const Vr41xxRtclView& before);
    std::optional<uint64_t> CompletePair(int ch, uint32_t reload);
    void OnAbsorbed(int ch, uint64_t phase) { census_.OnAbsorbed(ch, phase); }
    void OnReach(int ch) { census_.OnReach(ch); }
    void OnCntRead(int ch, const Vr41xxRtclView& v);
    void OnMatch(int ch) { grid_[ch] = true; }
    void Forget();
    void Report(int64_t now_ns) { census_.Report(now_ns); }

    void Save(StateWriter& w, uint64_t now, const Vr41xxRtclView (&v)[2]) const;
    void Restore(StateReader& r, uint64_t now, const Vr41xxRtclView (&v)[2]);

private:
    static constexpr uint64_t kNoPeriod = UINT64_MAX;

    Vr41xxRtclCensus census_;
    bool     grid_[2]          = {false, false};
    bool     pending_[2]       = {false, false};
    uint64_t pending_grid_[2]  = {0u, 0u};
    uint64_t banked_period_[2] = {kNoPeriod, kNoPeriod};
};
