#include "imx31_uart_impl.h"

namespace {

/* MCIMX31RM Table 31-2: UART5 at 0x43FB_4000. First UART touched on Zune Keel —
   the ACSSERV.DLL service probes it on the DefaultApp-launch path. */
class Imx31Uart5 : public cerf_imx31_uart_detail::Imx31UartImpl<0x43FB4000u, 5> {
    using Imx31UartImpl::Imx31UartImpl;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Uart5);
