#pragma once

#include "../intel_command_set_flash.h"

#include <cstdint>

/* Intel StrataFlash K3/K18 (Intel order 290737) Table 21: mfr 0x89, "K3 256 Mb
   Device Code 0x1 0x8803"; section 2.6: 64-Kword blocks, 256 blocks, x16. */
class Intel28F256K3 : public IntelCommandSetFlash {
public:
    using IntelCommandSetFlash::IntelCommandSetFlash;

protected:
    uint16_t Manufacturer() const override { return 0x0089u; }
    uint16_t Device()       const override { return 0x8803u; }
    uint32_t ChipEraseBlockBytes() const override { return 0x20000u; }
    uint32_t DeviceWidth() const override { return 2u; }
};
