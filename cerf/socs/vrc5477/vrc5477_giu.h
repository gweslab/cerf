#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>

class Vrc5477Intc;

class Vrc5477Giu : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override;
    uint32_t MmioSize() const override;

    void WriteWord(uint32_t addr, uint32_t value) override;

    void DriveInterruptInput(bool active);

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    void DriveSource();

    Vrc5477Intc* intc_    = nullptr;
    bool         input_   = false;
    bool         latched_ = false;
    bool         line_    = false;
};
