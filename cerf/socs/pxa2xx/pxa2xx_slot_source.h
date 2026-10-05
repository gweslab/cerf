#pragma once

#include <cstdint>

class Pxa2xxSlotSource {
public:
    virtual ~Pxa2xxSlotSource() = default;

    virtual uint64_t Count(uint64_t frames) const = 0;
    virtual bool     FrameOfSlot(uint64_t slot, uint64_t& frame) const = 0;
    virtual void     Prune(uint64_t settled) = 0;
};
