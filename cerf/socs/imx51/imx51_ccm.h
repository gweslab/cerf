#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../freescale_timer_clocks.h"

#include <array>
#include <cstdint>
#include <functional>
#include <vector>

class Imx51ClockInput;
class Imx51CortexA8Platform;

class Imx51Ccm : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x73FD4000u; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    uint64_t PerclkRootHz() const;
    uint64_t IpgClkHz() const;
    uint32_t ClockGate(uint32_t ccgr, uint32_t index) const;
    bool     ClockRunsIn(uint32_t ccgr, uint32_t index, FreescaleLowPowerMode mode) const;
    uint32_t WfiLowPowerMode() const;

    void RegisterRateListener(std::function<void()> fn);
    void RegisterGateListener(std::function<void()> fn);
    void ApplyRates();

private:
    static constexpr uint32_t kSize = 0x00001000u;

    uint32_t Reg(uint32_t off) const { return regs_[off >> 2]; }

    void     ResetRegisters();
    void     NotifyGates();
    uint64_t ArmClkHz() const;
    uint64_t LpApmHz() const;
    uint64_t StepClkHz() const;
    uint64_t Pll1SwClkHz() const;
    uint64_t Pll2SwClkHz() const;
    uint64_t Pll3SwClkHz() const;
    uint64_t PeriphApmClkHz() const;
    uint64_t MainBusClkHz() const;
    uint64_t DividedHz(uint64_t hz, uint64_t divider, const char* clock) const;

    const Imx51ClockInput*             input_ = nullptr;
    const Imx51CortexA8Platform*       platform_ = nullptr;
    uint64_t                           applied_hz_ = 0u;
    std::vector<std::function<void()>> listeners_;
    std::vector<std::function<void()>> gate_listeners_;
    std::array<uint32_t, kSize / 4>    regs_{};
};
