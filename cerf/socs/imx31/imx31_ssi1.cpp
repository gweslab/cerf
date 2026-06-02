#include "imx31_ssi_impl.h"

namespace {

/* MCIMX31RM Table 45-4: SSI1 at 0x43FA0000. */
class Imx31Ssi1 : public cerf_imx31_ssi_detail::Imx31SsiImpl<0x43FA0000u> {
    using Imx31SsiImpl::Imx31SsiImpl;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Ssi1);
