#include "../vr41xx/vr41xx_piu_impl.h"

#include <cstdint>

namespace {

using cerf_vr41xx_piu_detail::Vr41xxPiuBase;
using cerf_vr41xx_piu_detail::Vr41xxPiuModel;

/* VR4121 PIU (UM Table 20-1): PIUCNTREG..PIUCIVLREG at 0x0B000122-0x0B00013E and the
   data buffers at 0x0B0002A0-0x0B0002BE. */
constexpr Vr41xxPiuModel kModel = {
    /*base=*/0x0B000120u,
    /*size=*/0x20u,
    /*piu2_base=*/0x0B0002A0u,
    /*piu2_size=*/0x20u,
    /* PIUSIVLREG SCANINTVAL(10:0), RTCRST and after-reset rows 0x00A7 (UM 20.3.3). */
    /*sivl_power_on=*/0x00A7u,
    /* PIUCNTREG D15:14 are RFU, "0 is returned after a read" - the VR4102's D14 PENSTP
       does not exist here (UM 20.3.1). */
    /*has_penstp=*/false,
    /* "PENSTC does not change while PENCHGINTR is set to 1, even if the touch panel
       contact state changes between release and touch" (UM 20.3.1, 20.3.2). */
    /*penstc_latched_by_penchg=*/true,
};

class Vr4121Piu : public Vr41xxPiuBase<SocFamily::VR4121, kModel> {
public:
    using Vr41xxPiuBase::Vr41xxPiuBase;
};

}  /* namespace */

REGISTER_SERVICE_AS(Vr4121Piu, Vr41xxPiu);
