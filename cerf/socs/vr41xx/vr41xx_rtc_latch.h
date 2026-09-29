#pragma once

#include <cstdint>

class StateReader;
class StateWriter;

class Vr41xxRtcLatch {
public:
    Vr41xxRtcLatch(uint32_t halves, uint64_t mask) : halves_(halves), mask_(mask) {}

    bool     Write(uint32_t half, uint16_t value);
    bool     Written(uint32_t half) const { return (written_ & (1u << half)) != 0u; }
    bool     Open() const { return written_ != 0u; }
    uint64_t Value() const { return value_; }
    uint16_t Half(uint32_t half) const {
        return static_cast<uint16_t>((value_ >> (half * 16u)) & 0xFFFFu);
    }
    void Clear();

    void Save(StateWriter& w, const char* value_name, const char* written_name) const;
    void Restore(StateReader& r, const char* value_name, const char* written_name);

private:
    uint32_t halves_;
    uint64_t mask_;
    uint64_t value_   = 0;
    uint8_t  written_ = 0;
};
