#pragma once

#include "../pxa2xx/pxa2xx_gpio.h"

using Pxa255GpioSerialSlave = Pxa2xxGpioSerialSlave;

/* PXA255 GPIO, 3 banks x 32 pins (§4.1.3, base 0x40E00000, Table 4-49). */
class Pxa255Gpio : public Pxa2xxGpio {
public:
    using Pxa2xxGpio::Pxa2xxGpio;

    bool ShouldRegister() override;

protected:
    uint32_t BankCount() const override { return 3u; }
    uint32_t GafrCount() const override { return 6u; }

    /* Table 4-35 ICPR: GPIO0 edge -> bit 8, GPIO1 edge -> bit 9, any
       GPIO[84:2] edge -> the collective bit 10 (GPIO 64-84 = bank2 bits 0-20). */
    uint32_t CollectiveMask(uint32_t bank) const override {
        static constexpr uint32_t kMask[3] = { ~0x3u, 0xFFFFFFFFu, 0x001FFFFFu };
        return kMask[bank];
    }
};
