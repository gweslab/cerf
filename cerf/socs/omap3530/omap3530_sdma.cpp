#include "omap3530_sdma.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"

bool Omap3530Sdma::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::OMAP3530;
}

REGISTER_SERVICE(Omap3530Sdma);
