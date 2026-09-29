#include "vr41xx_rtcl_rephase.h"

#include "../../state/state_stream.h"

void Vr41xxRtclRephase::OnPairStart(int ch, bool repeat_half, uint64_t now,
                                    const Vr41xxRtclView& v) {
    using Pair = Vr41xxRtclCensus::Pair;
    if (repeat_half) census_.OnRepeatHalf(ch);
    pending_[ch] = false;
    const uint64_t grid_offset = v.periods * v.reload;
    if (v.reload == 0u || !grid_[ch]) {
        census_.OnPairStart(ch, Pair::NoGrid, 0u);
    } else if (v.latched || v.periods > v.ack) {
        census_.OnPairStart(ch, Pair::Latched, 0u);
    } else if (banked_period_[ch] == v.periods) {
        census_.OnPairStart(ch, Pair::Banked, 0u);
    } else if (now - v.anchor <= grid_offset) {
        census_.OnPairStart(ch, Pair::Zero, 0u);
    } else {
        pending_[ch]      = true;
        pending_grid_[ch] = v.anchor + grid_offset;
        census_.OnPairStart(ch, Pair::Absorbable, now - pending_grid_[ch]);
    }
    banked_period_[ch] = kNoPeriod;
}

std::optional<uint64_t> Vr41xxRtclRephase::CompletePair(int ch, uint32_t reload) {
    const bool pending = pending_[ch];
    pending_[ch]       = false;
    if (reload == 0u) {
        grid_[ch] = false;
        return std::nullopt;
    }
    if (!pending || ch != kTickChannel) return std::nullopt;
    return pending_grid_[ch];
}

void Vr41xxRtclRephase::OnCntRead(int ch, const Vr41xxRtclView& v) {
    const bool clear = !v.latched && v.periods <= v.ack;
    census_.OnCntRead(ch, clear);
    if (clear) banked_period_[ch] = v.periods;
}

void Vr41xxRtclRephase::Forget() {
    for (int ch = 0; ch < 2; ++ch) {
        grid_[ch]          = false;
        pending_[ch]       = false;
        pending_grid_[ch]  = 0u;
        banked_period_[ch] = kNoPeriod;
    }
}

void Vr41xxRtclRephase::Save(StateWriter& w, uint64_t now, const Vr41xxRtclView (&v)[2]) const {
    for (int ch = 0; ch < 2; ++ch) {
        w.Write<uint8_t>("rtcl_grid", grid_[ch] ? 1u : 0u);
        w.Write<uint8_t>("rtcl_pending", pending_[ch] ? 1u : 0u);
        w.Write<uint64_t>("rtcl_pending_back", pending_[ch] ? now - pending_grid_[ch] : 0u);
        w.Write<uint8_t>("rtcl_banked", banked_period_[ch] == v[ch].periods ? 1u : 0u);
    }
}

void Vr41xxRtclRephase::Restore(StateReader& r, uint64_t now, const Vr41xxRtclView (&v)[2]) {
    for (int ch = 0; ch < 2; ++ch) {
        uint8_t  grid = 0, pending = 0, banked = 0;
        uint64_t back = 0;
        r.Read("rtcl_grid", grid);
        r.Read("rtcl_pending", pending);
        r.Read("rtcl_pending_back", back);
        r.Read("rtcl_banked", banked);
        grid_[ch]          = grid != 0u;
        pending_[ch]       = pending != 0u;
        pending_grid_[ch]  = now - back;
        banked_period_[ch] = banked != 0u ? v[ch].periods : kNoPeriod;
    }
}
