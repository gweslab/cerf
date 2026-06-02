#include "imx31_ssi_impl.h"

namespace {

/* MCIMX31RM Table 45-4: SSI2 at 0x50014000. */
class Imx31Ssi2 : public cerf_imx31_ssi_detail::Imx31SsiImpl<0x50014000u> {
    using Imx31SsiImpl::Imx31SsiImpl;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Ssi2);
