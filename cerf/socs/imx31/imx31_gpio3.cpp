#include "imx31_gpio_impl.h"

namespace {

/* MCIMX31RM Table 5-3: GPIO3 at 0x53FA_4000. */
class Imx31Gpio3 : public cerf_imx31_gpio_detail::Imx31GpioImpl<0x53FA4000u> {
    using Imx31GpioImpl::Imx31GpioImpl;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Gpio3);
