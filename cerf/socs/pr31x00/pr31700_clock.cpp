#include "pr31x00_clock.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "pr31700_id.h"

namespace {

class Pr31700Clock : public Pr31x00Clock {
public:
    using Pr31x00Clock::Pr31x00Clock;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Pr31700;
    }

protected:
    /* "CORECLK - same rate as CLK2X ... used as master clock for CPU core" (TMPR3911 §6.2.2 p6-5). */
    uint64_t Clk2xPerCpuClock() const override { return 1u; }
};

}  // namespace

REGISTER_SERVICE_AS(Pr31700Clock, Pr31x00Clock);
