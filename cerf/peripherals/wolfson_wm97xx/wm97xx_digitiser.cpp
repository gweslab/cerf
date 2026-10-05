#include "wm97xx_digitiser.h"

#include "../../state/state_stream.h"

#include <algorithm>

bool Wm97xxDigitiser::Sequence::operator==(const Sequence& o) const {
    if (delay != o.delay || period != o.period || count != o.count || pen_gated != o.pen_gated ||
        to_slot != o.to_slot) {
        return false;
    }
    return std::equal(tags, tags + count, o.tags);
}

/* Wolfson WM9705 page 46 (Table 26): the conversion rate "is the MAXIMUM that may be obtained ... if
   the number of conversions to be performed, and the delay applied by the DEL[3-0] bits to each
   conversion, add up to a time greater than the nominal period". */
uint64_t Wm97xxDigitiser::Period(const Burst& b) {
    return b.polled ? SetSpan(b) : std::max<uint64_t>(b.seq.period, SetSpan(b));
}

/* Wolfson WM9705 Figure 22 (page 45): a conversion requested in frame w runs DELAY from frame w + 1
   and CONVERT in the frame after, and its result is available from the next frame. */
uint64_t Wm97xxDigitiser::ResultFrame(const Burst& b, uint64_t k) {
    return b.start + (k / b.seq.count) * Period(b) + (k % b.seq.count + 1u) * Step(b);
}

uint64_t Wm97xxDigitiser::Conversions(const Burst& b, uint64_t frames) {
    const uint64_t limit = b.cut == kOpen ? frames : std::min(frames, b.cut + 1u);
    if (limit <= b.start + Step(b)) return 0u;
    const uint64_t x    = limit - 1u - b.start;
    const uint64_t span = SetSpan(b);
    const uint64_t pe   = Period(b);
    uint64_t full = x >= span ? (x - span) / pe + 1u : 0u;
    full = std::min(full, b.sets);
    uint64_t partial = 0u;
    if (full < b.sets && x >= full * pe) {
        partial = std::min<uint64_t>((x - full * pe) / Step(b), b.seq.count);
    }
    return full * b.seq.count + partial;
}

uint64_t Wm97xxDigitiser::Total(const Burst& b) {
    if (b.cut != kOpen) return Conversions(b, b.cut + 1u);
    return b.sets == kOpen ? kOpen : b.sets * b.seq.count;
}

uint64_t Wm97xxDigitiser::LastFrame(const Burst& b) {
    const uint64_t total = Total(b);
    if (total == kOpen) return kOpen;
    return total == 0u ? b.start : ResultFrame(b, total - 1u);
}

void Wm97xxDigitiser::Clear(bool pen_down) {
    ClearHistory(pen_down);
    continuous_ = false;
    config_     = Sequence{};
}

void Wm97xxDigitiser::ClearHistory(bool pen_down) {
    bursts_.clear();
    edges_.clear();
    pen0_         = pen_down;
    pruned_slots_ = 0u;
    has_pruned_   = false;
    pruned_last_  = Result{};
}

void Wm97xxDigitiser::CloseLast(uint64_t frame) {
    if (bursts_.empty()) return;
    Burst& b = bursts_.back();
    if (LastFrame(b) > frame) b.cut = std::min(b.cut, frame);
}

void Wm97xxDigitiser::OpenBurst(uint64_t start, const Sequence& seq, bool polled, bool trip) {
    Burst b;
    b.seq    = seq;
    b.start  = start;
    b.sets   = polled ? 1u : kOpen;
    b.cut    = kOpen;
    b.polled = polled;
    b.trip   = trip;
    bursts_.push_back(b);
}

void Wm97xxDigitiser::SetContinuous(uint64_t frame, const Sequence* seq) {
    if (seq != nullptr && continuous_ && *seq == config_) return;
    CloseLast(frame);
    continuous_ = seq != nullptr;
    if (!continuous_) return;
    config_ = *seq;
    if (!config_.pen_gated || PenDownAt(frame + 1u)) OpenBurst(frame + 1u, config_, false, false);
}

void Wm97xxDigitiser::StartPolled(uint64_t frame, const Sequence& seq, bool trip) {
    CloseLast(frame);
    continuous_ = false;
    OpenBurst(frame + 1u, seq, true, trip);
}

/* Wolfson WM9705 page 46: "Pen-down detection is performed after completion of each set of
   conversions"; with PDEN set "and a pen-down is NOT detected, then the conversion process will come
   to a stop, until the pen is once more returned to the screen". */
void Wm97xxDigitiser::SetPen(uint64_t frame, bool down) {
    if (PenDownAt(frame) == down) return;
    edges_.push_back(Edge{frame, down});
    if (!continuous_ || !config_.pen_gated) return;
    Burst* last = bursts_.empty() ? nullptr : &bursts_.back();
    const bool ours = last != nullptr && !last->polled && last->cut == kOpen;
    if (!down) {
        if (!ours || last->sets != kOpen) return;
        const uint64_t first_check = last->start + SetSpan(*last);
        last->sets = frame <= first_check ? 1u : (frame - first_check + Period(*last) - 1u) / Period(*last) + 1u;
        return;
    }
    if (ours && (last->sets == kOpen || LastFrame(*last) >= frame)) {
        last->sets = kOpen;
        return;
    }
    OpenBurst(frame, config_, false, false);
}

bool Wm97xxDigitiser::PenDownAt(uint64_t frame) const {
    bool down = pen0_;
    for (const Edge& e : edges_) {
        if (e.frame > frame) break;
        down = e.down;
    }
    return down;
}

bool Wm97xxDigitiser::Polling(uint64_t frame) const {
    if (bursts_.empty()) return false;
    const Burst& b = bursts_.back();
    return b.polled && b.cut == kOpen && frame < LastFrame(b);
}

bool Wm97xxDigitiser::Pending(uint64_t frame) const {
    return !bursts_.empty() && LastFrame(bursts_.back()) >= frame;
}

bool Wm97xxDigitiser::TripReached(uint64_t frames) const {
    for (const Burst& b : bursts_) {
        if (b.trip && Conversions(b, frames) != 0u) return true;
    }
    return false;
}

Wm97xxDigitiser::Result Wm97xxDigitiser::ResultOf(const Burst& b, uint64_t k) const {
    Result r;
    r.tag      = b.seq.tags[k % b.seq.count];
    r.pen_down = PenDownAt(ResultFrame(b, k));
    return r;
}

uint64_t Wm97xxDigitiser::SlotWordsBefore(uint64_t frames) const {
    uint64_t n = pruned_slots_;
    for (const Burst& b : bursts_) {
        if (b.seq.to_slot) n += Conversions(b, frames);
    }
    return n;
}

bool Wm97xxDigitiser::FrameOfSlotWord(uint64_t n, uint64_t& frame) const {
    if (n <= pruned_slots_) return false;
    uint64_t base = pruned_slots_;
    for (const Burst& b : bursts_) {
        if (!b.seq.to_slot) continue;
        const uint64_t total = Total(b);
        if (total == kOpen || n <= base + total) {
            frame = ResultFrame(b, n - base - 1u);
            return true;
        }
        base += total;
    }
    return false;
}

bool Wm97xxDigitiser::SlotWord(uint64_t n, Result& r) const {
    if (n <= pruned_slots_) return false;
    uint64_t base = pruned_slots_;
    for (const Burst& b : bursts_) {
        if (!b.seq.to_slot) continue;
        const uint64_t total = Total(b);
        if (total == kOpen || n <= base + total) {
            r = ResultOf(b, n - base - 1u);
            return true;
        }
        base += total;
    }
    return false;
}

bool Wm97xxDigitiser::LastResult(uint64_t frame, Result& r) const {
    for (auto it = bursts_.rbegin(); it != bursts_.rend(); ++it) {
        const uint64_t c = Conversions(*it, frame + 1u);
        if (c == 0u) continue;
        r = ResultOf(*it, c - 1u);
        return true;
    }
    if (!has_pruned_) return false;
    r = pruned_last_;
    return true;
}

void Wm97xxDigitiser::Prune(uint64_t frames) {
    while (bursts_.size() > 1u && LastFrame(bursts_.front()) < frames) {
        const Burst&   b     = bursts_.front();
        const uint64_t total = Total(b);
        if (total != 0u) {
            pruned_last_ = ResultOf(b, total - 1u);
            has_pruned_  = true;
        }
        if (b.seq.to_slot) pruned_slots_ += total;
        bursts_.erase(bursts_.begin());
    }
    const uint64_t keep = bursts_.empty() ? frames : std::min(frames, bursts_.front().start);
    size_t drop = 0;
    while (drop < edges_.size() && edges_[drop].frame <= keep) {
        pen0_ = edges_[drop].down;
        ++drop;
    }
    edges_.erase(edges_.begin(), edges_.begin() + static_cast<std::ptrdiff_t>(drop));
}

namespace {

void SaveSequence(StateWriter& w, const Wm97xxDigitiser::Sequence& s) {
    w.Write<uint32_t>("dig_seq_delay", s.delay);
    w.Write<uint32_t>("dig_seq_period", s.period);
    w.Write<uint32_t>("dig_seq_count", s.count);
    for (uint8_t t : s.tags) w.Write<uint8_t>("dig_seq_tag", t);
    w.Write<uint8_t>("dig_seq_pen_gated", s.pen_gated ? 1u : 0u);
    w.Write<uint8_t>("dig_seq_to_slot", s.to_slot ? 1u : 0u);
}

void RestoreSequence(StateReader& r, Wm97xxDigitiser::Sequence& s) {
    uint8_t gated = 0, slot = 0;
    r.Read("dig_seq_delay", s.delay);
    r.Read("dig_seq_period", s.period);
    r.Read("dig_seq_count", s.count);
    for (uint8_t& t : s.tags) r.Read("dig_seq_tag", t);
    r.Read("dig_seq_pen_gated", gated);
    r.Read("dig_seq_to_slot", slot);
    s.pen_gated = gated != 0u;
    s.to_slot   = slot != 0u;
}

}  // namespace

void Wm97xxDigitiser::Save(StateWriter& w) const {
    w.Write<uint32_t>("dig_bursts", static_cast<uint32_t>(bursts_.size()));
    for (const Burst& b : bursts_) {
        SaveSequence(w, b.seq);
        w.Write<uint64_t>("dig_burst_start", b.start);
        w.Write<uint64_t>("dig_burst_sets", b.sets);
        w.Write<uint64_t>("dig_burst_cut", b.cut);
        w.Write<uint8_t>("dig_burst_polled", b.polled ? 1u : 0u);
        w.Write<uint8_t>("dig_burst_trip", b.trip ? 1u : 0u);
    }
    w.Write<uint32_t>("dig_edges", static_cast<uint32_t>(edges_.size()));
    for (const Edge& e : edges_) {
        w.Write<uint64_t>("dig_edge_frame", e.frame);
        w.Write<uint8_t>("dig_edge_down", e.down ? 1u : 0u);
    }
    w.Write<uint8_t>("dig_pen0", pen0_ ? 1u : 0u);
    w.Write<uint8_t>("dig_continuous", continuous_ ? 1u : 0u);
    SaveSequence(w, config_);
    w.Write<uint64_t>("dig_pruned_slots", pruned_slots_);
    w.Write<uint8_t>("dig_has_pruned", has_pruned_ ? 1u : 0u);
    w.Write<uint8_t>("dig_pruned_tag", pruned_last_.tag);
    w.Write<uint8_t>("dig_pruned_pen", pruned_last_.pen_down ? 1u : 0u);
}

void Wm97xxDigitiser::Restore(StateReader& r) {
    uint32_t bursts = 0, edges = 0;
    r.Read("dig_bursts", bursts);
    bursts_.assign(bursts, Burst{});
    for (Burst& b : bursts_) {
        uint8_t polled = 0, trip = 0;
        RestoreSequence(r, b.seq);
        r.Read("dig_burst_start", b.start);
        r.Read("dig_burst_sets", b.sets);
        r.Read("dig_burst_cut", b.cut);
        r.Read("dig_burst_polled", polled);
        r.Read("dig_burst_trip", trip);
        b.polled = polled != 0u;
        b.trip   = trip != 0u;
    }
    r.Read("dig_edges", edges);
    edges_.assign(edges, Edge{});
    for (Edge& e : edges_) {
        uint8_t down = 0;
        r.Read("dig_edge_frame", e.frame);
        r.Read("dig_edge_down", down);
        e.down = down != 0u;
    }
    uint8_t pen0 = 0, continuous = 0, has_pruned = 0, pruned_pen = 0;
    r.Read("dig_pen0", pen0);
    r.Read("dig_continuous", continuous);
    RestoreSequence(r, config_);
    r.Read("dig_pruned_slots", pruned_slots_);
    r.Read("dig_has_pruned", has_pruned);
    r.Read("dig_pruned_tag", pruned_last_.tag);
    r.Read("dig_pruned_pen", pruned_pen);
    pen0_                 = pen0 != 0u;
    continuous_           = continuous != 0u;
    has_pruned_           = has_pruned != 0u;
    pruned_last_.pen_down = pruned_pen != 0u;
}
