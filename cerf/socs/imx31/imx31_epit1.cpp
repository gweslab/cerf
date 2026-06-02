#include "imx31_epit_impl.h"

namespace {

/* MCIMX31RM Table 33-5: EPIT1 at 0x53F9_4000. */
class Imx31Epit1 : public cerf_imx31_epit_detail::Imx31EpitImpl<0x53F94000u> {
    using Imx31EpitImpl::Imx31EpitImpl;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Epit1);
