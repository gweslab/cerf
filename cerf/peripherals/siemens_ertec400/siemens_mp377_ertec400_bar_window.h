#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>

class SiemensMp377Ertec400BarWindow : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;
    uint8_t ReadByte(uint32_t address) override;
    uint16_t ReadHalf(uint32_t address) override;
    uint32_t ReadWord(uint32_t address) override;
    void WriteByte(uint32_t address, uint8_t value) override;
    void WriteHalf(uint32_t address, uint16_t value) override;
    void WriteWord(uint32_t address, uint32_t value) override;
};
