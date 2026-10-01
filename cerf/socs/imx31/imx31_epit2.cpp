#include "../freescale_epit_impl.h"

#include "imx31_avic.h"
#include "imx31_id.h"

namespace {

/* EPIT2 @ 0x53F98000; AVIC source 27 (MCIMX31RM Table 2-3, p190). */
class Imx31Epit2 : public cerf_freescale_epit_detail::FreescaleEpitBase<
                       0x53F98000u, SocId::Imx31, FreescaleTimerUnit::kEpit2,
                       cerf_freescale_epit_detail::kCrWritableMx31,
                       cerf_freescale_epit_detail::kCrSwrKeepMx31> {
    using FreescaleEpitBase::FreescaleEpitBase;
    void AssertIrqLine()   override { emu_.Get<Imx31Avic>().AssertSource(27u); }
    void DeassertIrqLine() override { emu_.Get<Imx31Avic>().DeassertSource(27u); }
};

}  /* namespace */

REGISTER_SERVICE(Imx31Epit2);
