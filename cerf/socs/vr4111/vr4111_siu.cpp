#include "../vr41xx/vr41xx_siu_reset_csel.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"

namespace {

class Vr4111Siu : public Vr41xxSiuResetCsel {
public:
    using Vr41xxSiuResetCsel::Vr41xxSiuResetCsel;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::VR4111;
    }
};

}

REGISTER_SERVICE(Vr4111Siu);
