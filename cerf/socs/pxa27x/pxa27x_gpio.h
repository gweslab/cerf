#pragma once

#include "../pxa2xx/pxa2xx_gpio.h"

class Pxa27xGpio : public Pxa2xxGpio {
public:
    using Pxa2xxGpio::Pxa2xxGpio;

    bool ShouldRegister() override;

protected:
    uint32_t BankCount() const override { return 4u; }
    uint32_t GafrCount() const override { return 8u; }

    /* Intel PXA27x Developer's Manual 280000-001 page 24-31: "GPIO<120:2>
       together form a group ... GPIO<0> and GPIO<1> cause independent first-
       level interrupts." Table 24-40 (page 24-33) GEDR3 0x40E0_0148: "<31:25>
       reserved", "<24:0> R/W ED x (where x = 96 through 120)". */
    uint32_t CollectiveMask(uint32_t bank) const override {
        static constexpr uint32_t kMask[4] = {
            0xFFFFFFFCu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x01FFFFFFu,
        };
        return kMask[bank];
    }

    Reg Decode(uint32_t off, uint32_t* index) const override;
};
