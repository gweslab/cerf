#include "imx51_i2c_impl.h"

#include "../../peripherals/freescale_mc13892/mc13892_pmic.h"

namespace {

/* I2C2 @ 0x83FC4000, TZIC source 63 (MCIMX51RM Table 3-2; base from the BSP
   i2c.dll index->base table, index 2 = the registry `I2C2:` device). The
   MC13892 PMIC is the slave on this bus. */
class Imx51I2c2
    : public cerf_imx51_i2c_detail::Imx51I2cImpl<0x83FC4000u, 63, FreescaleModule::kI2c2> {
    using Imx51I2cImpl::Imx51I2cImpl;

    I2cSlave* WiredSlave() override { return emu_.TryGet<Mc13892Pmic>(); }
};

}  /* namespace */

REGISTER_SERVICE(Imx51I2c2);
