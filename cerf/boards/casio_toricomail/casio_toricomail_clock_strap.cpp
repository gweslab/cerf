#include "../../socs/vr41xx/vr41xx_clock_strap.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "casio_toricomail_id.h"

namespace {

class CasioToricomailClockStrap : public Vr41xxClockStrap {
public:
    using Vr41xxClockStrap::Vr41xxClockStrap;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::CasioToricomail;
    }

    uint32_t Clksel() const override { return 0x4u; }
};

}

REGISTER_SERVICE_AS(CasioToricomailClockStrap, Vr41xxClockStrap);
