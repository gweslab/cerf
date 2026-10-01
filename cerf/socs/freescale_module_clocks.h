#pragma once

#include "freescale_timer_clocks.h"

#include <cstdint>
#include <functional>

enum class FreescaleModule : uint8_t {
    kRom, kIim, kUart1, kUart2, kUart3, kUart5, kUart1Ipg, kUart2Ipg, kUart3Ipg, kUart5Ipg,
    kI2c1, kI2c2, kI2c3, kSdhc1, kEsdhc2, kSsi1, kSsi2, kSsi3, kEcspi1, kCspi2, kCspi3, kSdma,
    kUsbPhy, kUsboh3Clk60, kUsbotg, kGpu3dCore, kGpu3dMemory, kVpu, kNfc, kGpu2d, kAta, kOwire,
};

class FreescaleModuleClocks : public Service {
public:
    using Service::Service;

    virtual bool ModuleRunsIn(FreescaleModule module, FreescaleLowPowerMode mode) const = 0;

    virtual void RegisterGateListener(std::function<void()> fn) = 0;

    void RequireRunning(FreescaleModule module, const char* operation);
};
