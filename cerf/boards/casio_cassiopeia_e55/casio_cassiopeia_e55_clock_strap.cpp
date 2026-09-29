#include "../../socs/vr41xx/vr41xx_clock_strap.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "casio_cassiopeia_e55_id.h"

namespace {

class CasioCassiopeiaE55ClockStrap : public Vr41xxClockStrap {
public:
    using Vr41xxClockStrap::Vr41xxClockStrap;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::CasioCassiopeiaE55;
    }

    uint32_t Clksel() const override { return 0x3u; }
};

}

REGISTER_SERVICE_AS(CasioCassiopeiaE55ClockStrap, Vr41xxClockStrap);
