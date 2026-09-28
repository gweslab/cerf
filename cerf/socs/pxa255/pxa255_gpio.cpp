#include "pxa255_gpio.h"

#include "../../boards/board_context.h"
#include "pxa255_id.h"
#include "../../core/cerf_emulator.h"
#include "../guest_cpu_reset.h"

bool Pxa255Gpio::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Pxa255;
}

/* PXA255 Dev Man §4.1.3 Table 4-2 note: "All GPIO registers are initialized to
   0x0 at reset"; §4.1.1: "the GPIO logic loses power during sleep mode". */
void Pxa255Gpio::OnReady() {
    Pxa2xxGpio::OnReady();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        ResetRegisters(emu_.Get<GuestCpuReset>().DeliveredResetWasResume());
    });
}

REGISTER_SERVICE(Pxa255Gpio);
