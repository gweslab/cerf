#pragma once

#include "../../core/service.h"
#include "../freescale_timer_clocks.h"

#include <cstdint>
#include <functional>
#include <vector>

class FreescaleModuleClocks;

class Imx51UsbTransceiverClocks : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    void RegisterChangeListener(std::function<void(FreescaleLowPowerMode)> fn);

    bool CoreClockRuns(uint32_t core, uint32_t portsc, uint32_t phy_ctrl0, uint32_t usb_ctrl1,
                       FreescaleLowPowerMode mode) const;

private:
    bool UtmiPhyClockRuns(uint32_t portsc, uint32_t phy_ctrl0, FreescaleLowPowerMode mode) const;
    void Notify(FreescaleLowPowerMode mode);

    FreescaleModuleClocks* modules_      = nullptr;
    FreescaleTimerClocks*  timer_clocks_ = nullptr;
    std::vector<std::function<void(FreescaleLowPowerMode)>> listeners_;
};
