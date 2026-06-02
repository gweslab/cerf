#include "imx31_i2c_impl.h"

namespace {

/* MCIMX31RM Table 26-3: I2C2 at 0x43F98000. */
class Imx31I2c2 : public cerf_imx31_i2c_detail::Imx31I2cImpl<0x43F98000u> {
    using Imx31I2cImpl::Imx31I2cImpl;
};

}  /* namespace */

REGISTER_SERVICE(Imx31I2c2);
