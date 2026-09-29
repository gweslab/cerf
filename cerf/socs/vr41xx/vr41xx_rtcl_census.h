#pragma once

#include <cstdint>

class Vr41xxRtclCensus {
public:
    enum class Pair { NoGrid, Latched, Banked, Zero, Absorbable };

    void OnPairStart(int ch, Pair kind, uint64_t phase_tk);
    void OnReach(int ch);
    void OnAbsorbed(int ch, uint64_t phase_tk);
    void OnRepeatHalf(int ch);
    void OnCntRead(int ch, bool bit_clear);
    void Report(int64_t now_ns);

private:
    struct Channel {
        uint32_t pairs         = 0;
        uint32_t no_grid       = 0;
        uint32_t absorbed      = 0;
        uint64_t absorbed_tk   = 0;
        uint32_t latched       = 0;
        uint32_t banked        = 0;
        uint32_t zero          = 0;
        uint32_t absorbable    = 0;
        uint64_t absorbable_tk = 0;
        uint32_t reach         = 0;
        uint32_t repeat_half   = 0;
        uint32_t cnt_reads     = 0;
        uint32_t cnt_reads_clr = 0;
    };

    int64_t report_ns_ = 0;
    Channel ch_[2];
};
