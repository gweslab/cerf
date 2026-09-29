#include "../vr41xx/vr41xx_rtc.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "vr4102_id.h"

#include <cstdint>

namespace {

class Vr4102Rtc : public Vr41xxRtc {
public:
    using Vr41xxRtc::Vr41xxRtc;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Vr4102;
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Vr4102Rtc, Vr41xxRtc);
