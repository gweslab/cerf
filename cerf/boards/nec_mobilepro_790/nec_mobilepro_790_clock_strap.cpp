#include "../../socs/vr41xx/vr41xx_clock_strap.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "nec_mobilepro_790_id.h"

namespace {

class NecMobilepro790ClockStrap : public Vr41xxClockStrap {
public:
    using Vr41xxClockStrap::Vr41xxClockStrap;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::NecMobilepro790;
    }

    uint32_t Clksel() const override { return 0x6u; }
};

}

REGISTER_SERVICE_AS(NecMobilepro790ClockStrap, Vr41xxClockStrap);
