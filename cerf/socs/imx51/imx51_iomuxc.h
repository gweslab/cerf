#pragma once

#include "../../peripherals/peripheral_base.h"

#include <array>
#include <cstdint>
#include <functional>
#include <vector>

class Imx51Iomuxc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x73FA8000u; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    void DriveWdog1WdogB(bool asserted);

    static bool MapsGpioPin(uint32_t gpio_base, uint32_t pin);
    uint32_t    InputPathMask(uint32_t gpio_base) const;
    uint32_t    GpioPadMask(uint32_t gpio_base) const;
    void        RegisterPadListener(std::function<void()> fn);

private:
    static constexpr uint32_t kSize      = 0x00004000u;
    static constexpr uint32_t kBoardPads = 5u;

    void CheckWdog1Pad() const;
    void ResetBoardPads();
    void NotifyPads();

    uint32_t                           gpio1_4_mux_  = 0u;
    bool                               wdog1_wdog_b_ = false;
    std::array<uint32_t, kBoardPads>   pad_mux_{};
    std::vector<std::function<void()>> pad_listeners_;
};
