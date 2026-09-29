#include "../guest_cycle_clock.h"

#include <algorithm>

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/arm_processor_config.h"
#include "arm_cpu.h"
#include "cpu_state.h"

#if CERF_DEV_MODE
#include <atomic>

#include "../../core/log.h"
#include "../../core/rate_probe.h"
#endif

namespace {

constexpr uint64_t kMaxSliceCycles = 1ull << 30;

class ArmGuestCycleClock : public GuestCycleClock {
public:
    using GuestCycleClock::GuestCycleClock;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Arm;
    }

    void OnReady() override {
        state_ = emu_.Get<ArmCpu>().State();
        hz_    = emu_.Get<ArmProcessorConfig>().CpuClockHz();
        GuestCycleClock::OnReady();
#if CERF_DEV_MODE
        emu_.Get<RateProbe>().RegisterStallDump([this] {
            const auto ld = [](uint32_t& word) {
                return std::atomic_ref<uint32_t>(word).load(std::memory_order_acquire);
            };
            const uint32_t counter  = ld(state_->guest_cycle_counter);
            const uint32_t folded   = ld(state_->guest_cycle_folded);
            const uint32_t hi32     = ld(state_->guest_cycle_hi);
            const uint32_t deadline = ld(state_->guest_cycle_deadline);
            const uint64_t hi       = hi32 + (counter < folded ? 1u : 0u);
            LOG(Jit, "[CYCLECLK] stall pc=0x%08X counter=%u deadline=%u (%+d) "
                     "hi=%u folded=%u cycles=%llu chain_exit=0x%X irq_pend=%u "
                     "deep_sleep=%u lag_ms_at_last_guest_s=%lld hz=%llu\n",
                ld(state_->gprs[ArmGpr::kR15]), counter, deadline,
                static_cast<int32_t>(counter - deadline), hi32, folded,
                static_cast<unsigned long long>((hi << 32) | counter),
                ld(state_->chain_exit_request), ld(state_->irq_interrupt_pending),
                ld(state_->deep_sleep),
                static_cast<long long>(LagNsAtLastSecond() / 1000000),
                static_cast<unsigned long long>(CpuHz()));
        });
#endif
    }

protected:
    Rate InitialRate() override { return Rate{hz_, 1u}; }

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
    ArmCpuState* state_ = nullptr;
    uint32_t     hz_    = 0;
};

}

REGISTER_SERVICE_AS(ArmGuestCycleClock, GuestCycleClock);
