#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../jit/mips/mips_core_clock.h"
#include "vr4122_clock_state.h"
#include "vr4122_id.h"

namespace {

class Vr4122CoreClock : public MipsCoreClock {
public:
    using MipsCoreClock::MipsCoreClock;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Vr4122;
    }

    void OnReady() override { state_ = &emu_.Get<Vr4122ClockState>(); }

    GuestCycleClock::Rate ResetRate() const override { return state_->ResetRate(); }
    uint64_t CyclesPerCountTick() const override { return state_->CyclesPerCountTick(); }
    uint64_t CyclesPerTclkCounterTick() const override { return state_->CyclesPerTclkCounterTick(); }

private:
    const Vr4122ClockState* state_ = nullptr;
};

}

REGISTER_SERVICE_AS(Vr4122CoreClock, MipsCoreClock);
