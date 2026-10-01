#include "../freescale_epit_impl.h"

#include "../irq_controller.h"
#include "imx51_id.h"

namespace {

/* EPIT1 @ 0x73FAC000; TZIC source 40 (MCIMX51RM Table 3-2, ARM Domain
   Interrupt Summary). */
class Imx51Epit1 : public cerf_freescale_epit_detail::FreescaleEpitBase<
                       0x73FAC000u, SocId::Imx51, FreescaleTimerUnit::kEpit1,
                       cerf_freescale_epit_detail::kCrWritableMx51,
                       cerf_freescale_epit_detail::kCrSwrKeepMx51> {
    using FreescaleEpitBase::FreescaleEpitBase;
    void AssertIrqLine()   override { emu_.Get<IrqController>().AssertIrq(40); }
    void DeassertIrqLine() override { emu_.Get<IrqController>().DeAssertIrq(40); }
};

}  /* namespace */

REGISTER_SERVICE(Imx51Epit1);
