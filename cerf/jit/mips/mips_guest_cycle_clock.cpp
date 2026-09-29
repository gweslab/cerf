#include "../guest_cycle_clock.h"

#include <algorithm>

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "mips_core_clock.h"
#include "mips_cpu.h"
#include "mips_cpu_state.h"

namespace {

constexpr uint64_t kMaxSliceCycles = 1ull << 30;

class MipsGuestCycleClock : public GuestCycleClock {
public:
    using GuestCycleClock::GuestCycleClock;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Mips;
    }

    void OnReady() override {
        state_ = emu_.Get<MipsCpu>().State();
        rate_  = emu_.Get<MipsCoreClock>().ResetRate();
        GuestCycleClock::OnReady();
    }

protected:
    Rate InitialRate() override { return rate_; }

    uint64_t CyclesNow() override {
        const uint32_t c = state_->guest_cycle_counter;
        if (c < state_->guest_cycle_folded) ++state_->guest_cycle_hi;
        state_->guest_cycle_folded = c;
        return (static_cast<uint64_t>(state_->guest_cycle_hi) << 32) | c;
    }

    void SetCycles(uint64_t cycles) override {
        state_->guest_cycle_hi      = static_cast<uint32_t>(cycles >> 32);
        state_->guest_cycle_counter = static_cast<uint32_t>(cycles);
        state_->guest_cycle_folded  = static_cast<uint32_t>(cycles);
    }

    void PublishDeadline(uint64_t cycles_ahead) override {
        state_->guest_cycle_deadline =
            state_->guest_cycle_counter +
            static_cast<uint32_t>(std::min(cycles_ahead, kMaxSliceCycles));
    }

private:
    MipsCpuState* state_ = nullptr;
    Rate          rate_;
};

}

REGISTER_SERVICE_AS(MipsGuestCycleClock, GuestCycleClock);
