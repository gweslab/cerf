#pragma once

#include "../peripheral_base.h"

#include <atomic>
#include <cstdint>

class CerfVirtPointer : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override;
    uint32_t MmioSize() const override;
    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    void SetPointer(uint32_t nx, uint32_t ny, uint32_t buttons);
    void AddWheel(int delta);
    void ClearButtons();

private:
    void Bump();

    std::atomic<uint32_t> x_{0};
    std::atomic<uint32_t> y_{0};
    std::atomic<uint32_t> buttons_{0};
    std::atomic<uint32_t> wheel_{0};
    std::atomic<uint32_t> seq_{0};
};
