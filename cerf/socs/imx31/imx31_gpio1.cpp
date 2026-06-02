#include "imx31_gpio_impl.h"

namespace {

/* MCIMX31RM Table 5-3: GPIO1 at 0x53FC_C000. */
class Imx31Gpio1 : public cerf_imx31_gpio_detail::Imx31GpioImpl<0x53FCC000u> {
    using Imx31GpioImpl::Imx31GpioImpl;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Gpio1);
