#include "pxa2xx_frame_slot_law.h"

#include "../../state/state_stream.h"

#include <algorithm>
#include <limits>
#include <string>

namespace {

constexpr uint64_t kOpen = std::numeric_limits<uint64_t>::max();

}  // namespace

void Pxa2xxFrameSlotLaw::Reset(uint64_t frame, uint32_t rate) {
    base_count_ = 0u;
    segments_.assign(1u, Segment{frame, rate});
}

void Pxa2xxFrameSlotLaw::Change(uint64_t frame, uint32_t rate) {
    if (segments_.empty()) {
        Reset(frame, rate);
        return;
    }
    if (segments_.back().rate == rate) return;
    if (segments_.back().start >= frame) {
        segments_.back().rate = rate;
        return;
    }
    segments_.push_back(Segment{frame, rate});
}

void Pxa2xxFrameSlotLaw::Prune(uint64_t settled) {
    while (segments_.size() > 1u && segments_[1].start <= settled) {
        base_count_ += Slots(segments_[1].start - segments_[0].start, segments_[0].rate);
        segments_.erase(segments_.begin());
    }
}

uint32_t Pxa2xxFrameSlotLaw::RateAt(uint64_t frame) const {
    uint32_t rate = 0u;
    for (const Segment& s : segments_) {
        if (s.start > frame) break;
        rate = s.rate;
    }
    return rate;
}

/* AC '97 Component Specification Revision 2.1 Appendix A.3 (page 62): "in passing a 44.1 kHz
   stream across the AC-link, for every 480 audio output frames that are sent across, 441 of
   them must contain valid sample data". */
uint64_t Pxa2xxFrameSlotLaw::Count(uint64_t frames) const {
    uint64_t acc = base_count_;
    for (size_t i = 0; i < segments_.size(); ++i) {
        const uint64_t start = segments_[i].start;
        if (frames <= start) break;
        const uint64_t end = i + 1u < segments_.size() ? segments_[i + 1u].start : kOpen;
        acc += Slots(std::min(frames, end) - start, segments_[i].rate);
    }
    return acc;
}

bool Pxa2xxFrameSlotLaw::FrameOfSlot(uint64_t slot, uint64_t& frame) const {
    uint64_t acc = base_count_;
    for (size_t i = 0; i < segments_.size(); ++i) {
        const Segment& s = segments_[i];
        const bool last = i + 1u == segments_.size();
        const uint64_t in_segment = last ? 0u : Slots(segments_[i + 1u].start - s.start, s.rate);
        if (s.rate != 0u && (last || slot <= acc + in_segment)) {
            const uint64_t j = slot - acc;
            frame = s.start + (j * frame_rate_ + s.rate - 1u) / s.rate - 1u;
            return true;
        }
        if (last) return false;
        acc += in_segment;
    }
    return false;
}

void Pxa2xxFrameSlotLaw::Save(StateWriter& w, const char* prefix) const {
    const std::string p = prefix;
    w.Write<uint64_t>((p + "_law_base").c_str(), base_count_);
    w.Write<uint32_t>((p + "_law_segments").c_str(), static_cast<uint32_t>(segments_.size()));
    for (const Segment& s : segments_) {
        w.Write<uint64_t>((p + "_law_start").c_str(), s.start);
        w.Write<uint32_t>((p + "_law_rate").c_str(), s.rate);
    }
}

void Pxa2xxFrameSlotLaw::Restore(StateReader& r, const char* prefix) {
    const std::string p = prefix;
    uint32_t n = 0;
    r.Read((p + "_law_base").c_str(), base_count_);
    r.Read((p + "_law_segments").c_str(), n);
    segments_.clear();
    for (uint32_t i = 0; i < n; ++i) {
        Segment s{};
        r.Read((p + "_law_start").c_str(), s.start);
        r.Read((p + "_law_rate").c_str(), s.rate);
        segments_.push_back(s);
    }
}
