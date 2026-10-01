#include "imx51_i2c_impl.h"

namespace {

/* I2C1 @ 0x83FC8000, TZIC source 62 (MCIMX51RM Table 3-2; base from the BSP
   i2c.dll index->base table, index 1). No slave wired yet. */
class Imx51I2c1
    : public cerf_imx51_i2c_detail::Imx51I2cImpl<0x83FC8000u, 62, FreescaleModule::kI2c1> {
    using Imx51I2cImpl::Imx51I2cImpl;
};

}  /* namespace */

REGISTER_SERVICE(Imx51I2c1);
