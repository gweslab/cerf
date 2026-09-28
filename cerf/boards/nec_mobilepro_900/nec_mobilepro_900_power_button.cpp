#include "../../core/service.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "nec_mobilepro_900_id.h"
#include "../../host/guest_deep_sleep.h"
#include "../../socs/pxa255/pxa255_gpio.h"

#include <cstdint>

namespace {

/* nec_mobilepro_900_hpc2000 XIP.BIN pwr.dll sub_11519D4 registers hw 0xD0000 to SYSINTR 31
   as a wake source; nk.exe hw type 0xD is sub_840BCEEC -> sub_840BCDAC pin 0, and
   sub_840BB5C4 arms it as PWER/PRER bit 0: a GPIO 0 rising edge. */
constexpr uint32_t kGpioUserWake = 0u;

class NecMobilepro900PowerButton : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecMobilepro900;
    }

    void OnReady() override {
        emu_.Get<GuestDeepSleep>().RegisterUserWakeInput([this] { Press(); });
    }

private:
    void Press() {
        auto& gpio = emu_.Get<Pxa255Gpio>();
        gpio.SetInputLevel(kGpioUserWake, true);
        gpio.SetInputLevel(kGpioUserWake, false);
    }
};

}

REGISTER_SERVICE(NecMobilepro900PowerButton);
