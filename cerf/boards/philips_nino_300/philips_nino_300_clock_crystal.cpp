#include "../../socs/pr31x00/pr31x00_clock_crystal.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "philips_nino_300_id.h"

namespace {

class PhilipsNino300ClockCrystal : public Pr31x00ClockCrystal {
public:
    using Pr31x00ClockCrystal::Pr31x00ClockCrystal;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::PhilipsNino300;
    }

    uint64_t FinHz() const override { return 9216000u; }
};

}

REGISTER_SERVICE_AS(PhilipsNino300ClockCrystal, Pr31x00ClockCrystal);
