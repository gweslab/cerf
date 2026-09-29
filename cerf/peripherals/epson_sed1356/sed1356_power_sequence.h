#pragma once

#include "../../core/service.h"

#include <cstdint>

class Sed1356PowerSequence : public Service {
public:
    using Service::Service;

    struct Delay {
        uint64_t frames = 0;
        uint64_t lines  = 0;
    };

    struct PanelDown {
        Delay status;
        Delay signals;
    };

    virtual uint32_t  LcdPowerOnLines(uint8_t power_save_reg) const = 0;
    virtual PanelDown LcdDisableToPanelDown(uint32_t panel_divisor,
                                            uint8_t power_save_reg) const = 0;
    virtual PanelDown PowerSaveToPanelDown() const = 0;
    virtual bool      LcdDisabledReadsPanelDown() const = 0;
    virtual bool      MemoryControllerPowersDown(uint8_t refresh_reg) const = 0;
};
