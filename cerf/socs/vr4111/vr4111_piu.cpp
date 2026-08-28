#include "../vr41xx/vr41xx_piu_impl.h"

#include <cstdint>

namespace {

using cerf_vr41xx_piu_detail::Vr41xxPiuBase;
using cerf_vr41xx_piu_detail::Vr41xxPiuModel;

/* VR4111 PIU (UM Table 20-1 p424): PIUCNTREG..PIUCIVLREG at 0x0B000122-0x0B00013E and the
   data buffers at 0x0B0002A0-0x0B0002BE. */
constexpr Vr41xxPiuModel kModel = {
    /*base=*/0x0B000120u,
    /*size=*/0x20u,
    /*piu2_base=*/0x0B0002A0u,
    /*piu2_size=*/0x20u,
    /* PIUSIVLREG SCANINTVAL(10:0), RTCRST and Other-resets rows both 0x00A7 (UM 20.3.3 p429). */
    /*sivl_power_on=*/0x00A7u,
    /* PIUCNTREG D15 and D14 are both Reserved, R, "Write 0 to these bits. 0 is returned after
       a read" - the VR4102's D14 PENSTP does not exist here (UM 20.3.1 p425). */
    /*has_penstp=*/false,
    /* "PENSTC does not change while PENCHGINTR is set to 1, even if the touch panel contact
       state changes between release and touch" (UM 20.3.1 p426). */
    /*penstc_latched_by_penchg=*/true,
};

class Vr4111Piu : public Vr41xxPiuBase<SocFamily::VR4111, kModel> {
public:
    using Vr41xxPiuBase::Vr41xxPiuBase;
};

}  /* namespace */

REGISTER_SERVICE_AS(Vr4111Piu, Vr41xxPiu);
