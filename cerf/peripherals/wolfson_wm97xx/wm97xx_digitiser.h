#pragma once

#include <cstdint>
#include <vector>

class StateReader;
class StateWriter;

class Wm97xxDigitiser {
public:
    static constexpr uint32_t kMaxConversions = 7u;

    struct Sequence {
        uint32_t delay     = 0;
        uint32_t period    = 0;
        uint32_t count     = 0;
        uint8_t  tags[kMaxConversions] = {};
        bool     pen_gated = false;
        bool     to_slot   = false;

        bool operator==(const Sequence& o) const;
    };

    struct Result {
        uint8_t tag      = 0;
        bool    pen_down = false;
    };

    void Clear(bool pen_down);
    void ClearHistory(bool pen_down);
    void SetContinuous(uint64_t frame, const Sequence* seq);
    void StartPolled(uint64_t frame, const Sequence& seq, bool trip);
    void SetPen(uint64_t frame, bool down);

    bool PenDownAt(uint64_t frame) const;
    bool Polling(uint64_t frame) const;
    bool Pending(uint64_t frame) const;
    bool TripReached(uint64_t frames) const;

    uint64_t SlotWordsBefore(uint64_t frames) const;
    bool     FrameOfSlotWord(uint64_t n, uint64_t& frame) const;
    bool     SlotWord(uint64_t n, Result& r) const;
    bool     LastResult(uint64_t frame, Result& r) const;
    void     Prune(uint64_t frames);

    void Save(StateWriter& w) const;
    void Restore(StateReader& r);

private:
    static constexpr uint64_t kOpen = UINT64_MAX;

    struct Burst {
        Sequence seq;
        uint64_t start  = 0;
        uint64_t sets   = 0;
        uint64_t cut    = 0;
        bool     polled = false;
        bool     trip   = false;
    };

    struct Edge {
        uint64_t frame = 0;
        bool     down  = false;
    };

    static uint64_t Step(const Burst& b) { return static_cast<uint64_t>(b.seq.delay) + 1u; }
    static uint64_t SetSpan(const Burst& b) { return b.seq.count * Step(b); }
    static uint64_t Period(const Burst& b);
    static uint64_t ResultFrame(const Burst& b, uint64_t k);
    static uint64_t Conversions(const Burst& b, uint64_t frames);
    static uint64_t Total(const Burst& b);
    static uint64_t LastFrame(const Burst& b);

    void CloseLast(uint64_t frame);
    void OpenBurst(uint64_t start, const Sequence& seq, bool polled, bool trip);
    Result ResultOf(const Burst& b, uint64_t k) const;

    std::vector<Burst> bursts_;
    std::vector<Edge>  edges_;
    bool     pen0_         = false;
    bool     continuous_   = false;
    Sequence config_;
    uint64_t pruned_slots_ = 0;
    bool     has_pruned_   = false;
    Result   pruned_last_;
};
