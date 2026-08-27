#include "../vr41xx/vr41xx_rtc.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"

#include <cstdint>

namespace {

/* VR4111 UM 11.2.8 p273: TClock = (18.432 MHz / CLKSP[4:0]) x 32, x 21.33 or x 16, selected by
   whichever of DIV2B/DIV3B/DIV4B is 0. CLKSPEEDREG D[15:13] and D[4:0] are R, Undefined on both
   the RTCRST and the Other-resets column. */
class Vr4111Rtc : public Vr41xxRtc {
public:
    using Vr41xxRtc::Vr41xxRtc;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::VR4111;
    }
    uint32_t TClockHz() const override { return 0u; }
};

}  /* namespace */

REGISTER_SERVICE_AS(Vr4111Rtc, Vr41xxRtc);
