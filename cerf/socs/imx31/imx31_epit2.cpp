#include "imx31_epit_impl.h"

namespace {

/* MCIMX31RM Table 33-5: EPIT2 at 0x53F9_8000. */
class Imx31Epit2 : public cerf_imx31_epit_detail::Imx31EpitImpl<0x53F98000u> {
    using Imx31EpitImpl::Imx31EpitImpl;
};

}  /* namespace */

REGISTER_SERVICE(Imx31Epit2);
