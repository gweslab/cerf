#include "pr31x00_clock.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "pr31500_id.h"

namespace {

class Pr31500Clock : public Pr31x00Clock {
public:
    using Pr31x00Clock::Pr31x00Clock;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Pr31500;
    }

protected:
    /* "40MHz operation frequency" and DCLKOUT "(nominal) 73.728 MHz" (PR31500 data sheet p.2, p.8),
       DCLKOUT = CLK2X in every row of TMPR3911 §6.2.1 p6-4. */
    uint64_t Clk2xPerCpuClock() const override { return 2u; }
};

}  // namespace

REGISTER_SERVICE_AS(Pr31500Clock, Pr31x00Clock);
