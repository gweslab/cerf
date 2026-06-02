#include "imx31_gpio_impl.h"

namespace {

/* MCIMX31RM Table 5-3: GPIO2 at 0x53FD_0000. */
class Imx31Gpio2 : public cerf_imx31_gpio_detail::Imx31GpioImpl<0x53FD0000u> {
    using Imx31GpioImpl::Imx31GpioImpl;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Gpio2);
