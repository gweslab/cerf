#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>

class Imx51CortexA8Platform : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x83FA0000u; }
    uint32_t MmioSize() const override { return 0x00004000u; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    bool DeepSleepRequestEnabled() const;

private:
    void ResetRegisters();

    uint32_t lpc_  = 0u;
    uint32_t icgc_ = 0u;
    uint32_t amc_  = 0u;
};
