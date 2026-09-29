#pragma once

#include "../../core/service.h"

#include <cstdint>

struct Omap3530MpuDpllSetting {
    uint32_t clken_pll;
    uint32_t clksel1_pll;
    uint32_t clksel2_pll;
};

struct Omap3530PeriphDpllSetting {
    uint32_t clken_pll;
    uint32_t clksel2_pll;
};

class Omap3530BoardClockSetup : public Service {
public:
    using Service::Service;

    virtual uint64_t OscSysClkHz() const = 0;

    virtual bool SysXtalinIsSquareClock() const = 0;

    virtual Omap3530MpuDpllSetting BootMpuDpll() const = 0;

    virtual Omap3530PeriphDpllSetting BootPeriphDpll() const = 0;

    virtual bool BootEnablesGpt1Clocks() const = 0;
};
