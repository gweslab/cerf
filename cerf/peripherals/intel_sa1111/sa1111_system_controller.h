#pragma once

#include "sa1111_unit.h"

#include <cstdint>
#include <functional>
#include <vector>

class Sa1111SystemController : public Sa1111Unit {
public:
    using Sa1111Unit::Sa1111Unit;

    bool ShouldRegister() override;

    uint32_t MmioBase() const override { return 0x40000200u; }
    uint32_t MmioSize() const override { return 0x00000200u; }

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    void RegisterClockListener(std::function<void()> fn);
    void NotifyClockListeners();

    void AudioFrameRate(uint64_t& num, uint64_t& den) const;
    bool PllRunningAtResetRate() const;
    uint32_t Skcdr() const { return regs_[1]; }
    bool I2sClockEnabled() const { return (regs_[0] & (1u << 2)) != 0u; }
    bool L3ClockEnabled()  const { return (regs_[0] & (1u << 3)) != 0u; }
    bool SspClockEnabled() const { return (regs_[0] & (1u << 4)) != 0u; }
    bool DmaClockEnabled() const { return (regs_[0] & (1u << 7)) != 0u; }

protected:
    void     OnUnitReady() override;
    void     OnChipReset(bool held) override;
    uint32_t UnitReadWord (uint32_t addr) override;
    void     UnitWriteWord(uint32_t addr, uint32_t value) override;

private:
    void LoadResetValues();
    void PllOutputRate(uint64_t& num, uint64_t& den) const;
    bool PllAtResetRate() const;

    std::vector<std::function<void()>> clock_listeners_;
    uint32_t regs_[9] = {};
};
