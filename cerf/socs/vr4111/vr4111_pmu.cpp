#include "../vr41xx/vr41xx_pmu_impl.h"

#include "../../core/cerf_emulator.h"
#include "../guest_cpu_reset.h"

#include <cstdint>
#include "vr4111_id.h"

namespace {

using cerf_vr41xx_pmu_detail::Vr41xxPmuBase;
using cerf_vr41xx_pmu_detail::Vr41xxPmuModel;

/* VR4111 PMU (UM Table 16-4): PMUINTREG@0x00, PMUCNTREG@0x02, PMUINT2REG@0x04,
   PMUCNT2REG@0x06, PMUWAITREG@0x08. RTC1 follows at 0x0B0000C0 (UM Table 6-10). */
constexpr Vr41xxPmuModel kModel = {
    /*base=*/0x0B0000A0u,
    /*size=*/0x20u,
    /* PMUINTREG (UM 16.2.1 p364-365), "Cleared to 0 when 1 is written": D15:12
       GPIO3:0INTR, D9 RTCINTR, D8 BATTINH, D5 TIMOUTRST, D4 RTCRST, D3 RSTSW,
       D2 DMSRST, D1 BATTINTR, D0 POWERSWINTR. D11 RFU reads 0, D10 DCDST is the
       DCD# pin state (both R). */
    /*int_w1c=*/0xF33Fu,
    /*int_sw_rw=*/0x00C0u,     /* D7:6 memo(1:0), "can be used by users freely" */
    /*int_power_on=*/0x0010u,  /* RTCRST column: D4 RTCRST = 1, every other bit 0 */
    /* PMUCNTREG (UM 16.2.2 p366): D15:12 GPIO3:0MSK, D11:8 GPIO3:0TRG, D7 STANDBY
       and D2 HALTIMERRST are R/W; D6:3 and D0 RFU read 0, D1 RFU reads 1. */
    /*cnt_writable=*/0xFF84u,
    /*cnt_fixed_read=*/0x0002u,
    /*cnt_power_on=*/0x8802u,  /* RTCRST column: D15 GPIO3MSK + D11 GPIO3TRG + D1 */
    /* PMUWAITREG (UM 16.2.5 p370): D13:0 WCOUNT, "Activation wait time = WCOUNT[13..0]
       x (1/32.768) ms"; D15:14 RFU. "This register is set to 0x2C00 ... after RTC
       reset"; its Other-resets row is "Hold the value before reset". */
    0x3FFFu,
    0x2C00u,
    0x0008u,   /* PMUINTREG D3 RSTSW, "RESET switch interrupt" */
    0x0010u,   /* PMUINTREG D4 RTCRST, "RTC reset detection"   */
    /* "This bit is not set to 1 when the POWER signal becomes high in the Hibernate
       mode (MPOWER = 0)" (UM 16.2.1 p365, POWERSWINTR). */
    0u,
    /* UM 16.2.2 p367: D6..3 "Write 0 to these bits", D1 "Write 1 to this bit", D0
       "Write 0 to this bit". */
    0x0079u,
    0x0002u,
    /* UM 16.2.1 p364: PMUINTREG "Other resets" row 0 in D15-D0. */
    0x0000u,
    0x0004u,   /* UM 16.2.1 p365: D2 DMSRST "Deadman's switch interrupt detection" */
};

class Vr4111Pmu : public Vr41xxPmuBase<SocId::Vr4111, kModel> {
public:
    using Vr41xxPmuBase::Vr41xxPmuBase;
};

}

REGISTER_SERVICE_AS(Vr4111Pmu, Vr41xxPmu);
