#include "../../jit/mips/mips_core_clock.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "vr5500_board_clock.h"
#include "vr5500_id.h"

namespace {

constexpr uint64_t kPClockPerCountTick = 2u;

class Vr5500CoreClock : public MipsCoreClock {
public:
    using MipsCoreClock::MipsCoreClock;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Vr5500;
    }

    GuestCycleClock::Rate ResetRate() const override {
        return GuestCycleClock::Rate{emu_.Get<Vr5500BoardClock>().PClockHz(), 1u};
    }

    uint64_t CyclesPerCountTick() const override { return kPClockPerCountTick; }
};

}

REGISTER_SERVICE_AS(Vr5500CoreClock, MipsCoreClock);
