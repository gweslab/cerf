#pragma once

#include "../freescale_gpio_impl.h"
#include "imx31_id.h"

/* MCIMX31RM Table 5-3: GPIO1 at 0x53FC_C000. */
class Imx31Gpio1
    : public cerf_freescale_gpio_detail::FreescaleGpioBase<0x53FCC000u, SocId::Imx31,
                                                           -1, -1, true> {
public:
    using FreescaleGpioBase::FreescaleGpioBase;

protected:
    void DrivePortIrqLine(bool asserted) override;
};
