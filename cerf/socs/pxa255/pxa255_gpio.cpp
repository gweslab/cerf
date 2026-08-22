#include "pxa255_gpio.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"

bool Pxa255Gpio::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::PXA25x;
}

REGISTER_SERVICE(Pxa255Gpio);
