#include "vr41xx_rtcl_census.h"

#include "../../core/log.h"

void Vr41xxRtclCensus::OnPairStart(int ch, Pair kind, uint64_t phase_tk) {
    Channel& c = ch_[ch];
    ++c.pairs;
    switch (kind) {
        case Pair::NoGrid:     ++c.no_grid;  break;
        case Pair::Latched:    ++c.latched;  break;
        case Pair::Banked:     ++c.banked;   break;
        case Pair::Zero:       ++c.zero;     break;
        case Pair::Absorbable: ++c.absorbable; c.absorbable_tk += phase_tk; break;
    }
}

void Vr41xxRtclCensus::OnReach(int ch) { ++ch_[ch].reach; }

void Vr41xxRtclCensus::OnAbsorbed(int ch, uint64_t phase_tk) {
    ++ch_[ch].absorbed;
    ch_[ch].absorbed_tk += phase_tk;
}

void Vr41xxRtclCensus::OnRepeatHalf(int ch) { ++ch_[ch].repeat_half; }

void Vr41xxRtclCensus::OnCntRead(int ch, bool bit_clear) {
    ++ch_[ch].cnt_reads;
    if (bit_clear) ++ch_[ch].cnt_reads_clr;
}

void Vr41xxRtclCensus::Report(int64_t now_ns) {
    if (report_ns_ == 0 || now_ns < report_ns_) { report_ns_ = now_ns; return; }
    if (now_ns - report_ns_ < 1000000000ll) return;
    report_ns_ = now_ns;
    if (ch_[0].pairs == 0 && ch_[0].cnt_reads == 0 && ch_[1].pairs == 0 && ch_[1].cnt_reads == 0)
        return;
    for (int ch = 0; ch < 2; ++ch) {
        const Channel& c = ch_[ch];
        LOG(SocRtc, "[RTCLXR] RTCL%d pairs=%u no_grid=%u latched=%u banked=%u zero=%u "
                    "absorbable=%u absorbable_tk=%llu reach=%u absorbed=%u absorbed_tk=%llu "
                    "repeat_half=%u cnt_reads=%u cnt_reads_clr=%u\n",
            ch + 1, c.pairs, c.no_grid, c.latched, c.banked, c.zero, c.absorbable,
            static_cast<unsigned long long>(c.absorbable_tk), c.reach, c.absorbed,
            static_cast<unsigned long long>(c.absorbed_tk), c.repeat_half, c.cnt_reads,
            c.cnt_reads_clr);
        ch_[ch] = Channel{};
    }
}
