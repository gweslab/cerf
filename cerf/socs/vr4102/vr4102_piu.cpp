#include "../vr41xx/vr41xx_piu_impl.h"

#include <cstdint>

namespace {

using cerf_vr41xx_piu_detail::Vr41xxPiuBase;
using cerf_vr41xx_piu_detail::Vr41xxPiuModel;

/* VR4102 PIU (UM Table 19-1): PIUCNTREG..PIUCIVLREG at 0x0B000122-0x0B00013E and the
   data buffers at 0x0B0002A0-0x0B0002BE. */
constexpr Vr41xxPiuModel kModel = {
    /*base=*/0x0B000120u,
    /*size=*/0x20u,
    /*piu2_base=*/0x0B0002A0u,
    /*piu2_size=*/0x20u,
    /* PIUSIVLREG SCANINTVAL(10:0), RTCRST and other-resets rows 0x0007 (UM 19.3.3). */
    /*sivl_power_on=*/0x0007u,
    /* PIUCNTREG D14 PENSTP, R/W: "Previous touch panel contact state" (UM 19.3.1). */
    /*has_penstp=*/true,
    /* PIUCNTREG D13 PENSTC, R: "Current touch panel contact state" (UM 19.3.1). */
    /*penstc_latched_by_penchg=*/false,
};

class Vr4102Piu : public Vr41xxPiuBase<SocFamily::VR4102, kModel> {
public:
    using Vr41xxPiuBase::Vr41xxPiuBase;
};

}  /* namespace */

REGISTER_SERVICE_AS(Vr4102Piu, Vr41xxPiu);
