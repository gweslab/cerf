#pragma once

#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_base.h"

class Iop13xxPmmrGuard : public Peripheral {
public:
    using Peripheral::Peripheral;
    bool ShouldRegister() override;
    void OnReady() override;
    uint32_t ReadWord(uint32_t addr) override;
    uint16_t ReadHalf(uint32_t addr) override;
    uint8_t ReadByte(uint32_t addr) override;
    void WriteWord(uint32_t addr, uint32_t value) override;
    void WriteHalf(uint32_t addr, uint16_t value) override;
    void WriteByte(uint32_t addr, uint8_t value) override;
};

template <uint32_t kBase, uint32_t kSize> class Iop13xxPmmrRange : public Iop13xxPmmrGuard {
public:
    using Iop13xxPmmrGuard::Iop13xxPmmrGuard;
    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }
};
