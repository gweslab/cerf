#include "../../cpu/vr5500/vr5500_board_clock.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "nec_rockhopper_id.h"

namespace {

class NecRockhopperVr5500BoardClock : public Vr5500BoardClock {
public:
    using Vr5500BoardClock::Vr5500BoardClock;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::NecRockhopper;
    }

    uint64_t PClockHz() const override { return 400000000u; }
};

}

REGISTER_SERVICE_AS(NecRockhopperVr5500BoardClock, Vr5500BoardClock);
