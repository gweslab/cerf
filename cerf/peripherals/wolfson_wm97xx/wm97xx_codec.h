#pragma once

#include "../ac97_codec.h"
#include "wm97xx_digitiser.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

class HostRequestChannel;

class Wm97xxCodec : public Ac97Codec {
public:
    using Ac97Codec::Ac97Codec;

    void OnReady() override;

    void SetPenPosition(uint16_t raw_x, uint16_t raw_y);
    void QueuePenEdge(bool down);
    void SetPenLineObserver(std::function<void(bool down)> fn) { pen_line_ = std::move(fn); }

    void     LinkStopped(uint64_t frame) override;
    uint64_t SlotWordsBefore(uint64_t frames) override;
    bool     FrameOfSlotWord(uint64_t n, uint64_t& frame) override;
    uint16_t SlotWord(uint64_t n) override;
    void     PruneSlotWords(uint64_t frames) override;
    void     PostRestore() override;

protected:
    static constexpr uint16_t kAdcMax        = 0x0FFFu;
    static constexpr uint32_t kRegDigitiserPower = 0x78u;

    virtual uint16_t ConversionData(uint8_t tag) = 0;
    virtual void     Reconfigure(uint64_t frame, bool poll) = 0;

    bool     DigitiserPowered();
    uint32_t DelayFrames(uint32_t del, uint16_t reg_value);
    uint16_t ResultWord(const Wm97xxDigitiser::Result& r);
    uint16_t LastResultWord(uint64_t frame, uint16_t held);
    uint16_t RawX() const { return raw_x_.load(std::memory_order_relaxed); }
    uint16_t RawY() const { return raw_y_.load(std::memory_order_relaxed); }
    void     RequireNoTrip(uint64_t frames);
    void     SavePen(StateWriter& w) const;
    void     RestorePen(StateReader& r);

    Wm97xxDigitiser digitiser_;
    bool            pen_down_ = false;

private:
    void SetPenDown(bool down);
    void DrainPenEdges();
    void WakeOnPen(bool linked, uint64_t frame);

    std::atomic<uint16_t>     raw_x_{0};
    std::atomic<uint16_t>     raw_y_{0};
    std::function<void(bool)> pen_line_;
    HostRequestChannel*       host_requests_ = nullptr;
    std::mutex                edge_mtx_;
    std::vector<bool>         edges_;
};
