#pragma once

#include "pxa2xx_slot_source.h"

#include <cstdint>
#include <vector>

class StateReader;
class StateWriter;

class Pxa2xxFrameSlotLaw : public Pxa2xxSlotSource {
public:
    explicit Pxa2xxFrameSlotLaw(uint32_t frame_rate) : frame_rate_(frame_rate) {}

    void Reset(uint64_t frame, uint32_t rate);
    void Change(uint64_t frame, uint32_t rate);
    void Prune(uint64_t settled) override;

    uint32_t RateAt(uint64_t frame) const;
    uint64_t Count(uint64_t frames) const override;
    bool     FrameOfSlot(uint64_t slot, uint64_t& frame) const override;

    void Save(StateWriter& w, const char* prefix) const;
    void Restore(StateReader& r, const char* prefix);

private:
    struct Segment {
        uint64_t start;
        uint32_t rate;
    };

    uint64_t Slots(uint64_t frames, uint32_t rate) const { return frames * rate / frame_rate_; }

    uint32_t frame_rate_;
    uint64_t base_count_ = 0;
    std::vector<Segment> segments_;
};
