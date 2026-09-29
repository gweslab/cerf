#include <string_view>

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../jit/mips/mips_core_clock.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "pr31x00_clock.h"

namespace {

class Pr31x00CoreClock : public MipsCoreClock {
public:
    using MipsCoreClock::MipsCoreClock;

    bool ShouldRegister() override {
        const std::string_view soc = emu_.Get<BoardContext>().GetSocId();
        return soc == SocId::Pr31500 || soc == SocId::Pr31700;
    }

    GuestCycleClock::Rate ResetRate() const override {
        return emu_.Get<Pr31x00Clock>().ResetCpuRate();
    }
};

}  // namespace

REGISTER_SERVICE_AS(Pr31x00CoreClock, MipsCoreClock);
