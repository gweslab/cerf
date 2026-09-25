#pragma once

#include <array>
#include <cstdint>

class StateReader;
class StateWriter;

class S3C2410IisTxFifo {
public:
    /* S3C2410A User Manual, printed p. 21-8: "two 64-byte FIFO ... 16-width and
       32-depth". */
    static constexpr uint32_t kDepth = 32u;

    void     Reset();
    void     Clear();
    bool     Reserve(uint32_t entries);
    void     Release(uint32_t entries);
    bool     Push(uint16_t sample);
    uint16_t Pop();
    uint32_t Count() const    { return count_; }
    uint32_t Reserved() const { return reserved_; }

    void Save(StateWriter& w) const;
    void Restore(StateReader& r);

private:
    std::array<uint16_t, kDepth> fifo_{};
    uint32_t                     head_     = 0u;
    uint32_t                     count_    = 0u;
    uint32_t                     reserved_ = 0u;
};
