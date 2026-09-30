#include "../../peripherals/intel_sa1111/sa1111_reset_line.h"

#include "../../core/cerf_emulator.h"
#include "../../socs/sa11xx/sa11xx_gpio.h"
#include "../board_context.h"
#include "jornada_720_id.h"

#include <cstdint>

namespace {

/* jornada720 jornada720.bin nk.exe sub_8004F8EC 0x8004F914 / 0x8004F930 / 0x8004F93C: GPSR,
   GPCR, GPSR of GPIO 20, then 0x8004F950 its first SA-1111 register store. */
constexpr uint32_t kGpio20 = 1u << 20;

class Jornada720Sa1111Reset : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Jornada720;
    }

    void OnReady() override {
        auto& line = emu_.Get<Sa1111ResetLine>();
        emu_.Get<Sa11xxGpio>().RegisterOutputObserver(
            [&line](uint32_t levels, uint32_t out_mask, bool resync) {
                using Pin = Sa1111ResetLine::Pin;
                const Pin pin = (out_mask & kGpio20) == 0u ? Pin::Floating
                              : (levels & kGpio20) != 0u   ? Pin::High
                                                           : Pin::Low;
                line.Drive(pin, resync);
            });
    }
};

}

REGISTER_SERVICE(Jornada720Sa1111Reset);
