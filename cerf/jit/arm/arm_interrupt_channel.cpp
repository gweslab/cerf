#include "arm_interrupt_channel.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../guest_cycle_clock.h"
#include "arm_cpu.h"
#include "cpu_state.h"

REGISTER_SERVICE(ArmInterruptChannel);

ArmInterruptChannel::~ArmInterruptChannel() {
    if (idle_event_) {
        CloseHandle(idle_event_);
        idle_event_ = nullptr;
    }
}

void ArmInterruptChannel::OnReady() {
    cpu_state_ = emu_.Get<ArmCpu>().State();
    clock_     = &emu_.Get<GuestCycleClock>();

    idle_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!idle_event_) {
        emu_.Get<Fatal>().Die(
            "ArmInterruptChannel: CreateEventW(idle_event) failed gle=%lu",
            GetLastError());
    }
}

void ArmInterruptChannel::SetInterruptPending() {
    const bool edge = irq_line_.exchange(1u, std::memory_order_acq_rel) == 0u;
    std::atomic_ref<uint32_t>(cpu_state_->chain_exit_request)
        .fetch_or(kChainExitIrq, std::memory_order_acq_rel);
    if (edge) {
        SetEvent(idle_event_);
    }
}

void ArmInterruptChannel::ClearInterruptPending() {
    irq_line_.store(0u, std::memory_order_release);
    std::atomic_ref<uint32_t>(cpu_state_->chain_exit_request)
        .fetch_and(~kChainExitIrq, std::memory_order_acq_rel);
}

void ArmInterruptChannel::SetIdleWake(bool level) {
    const uint32_t value = level ? 1u : 0u;
    const bool edge = idle_wake_line_.exchange(value, std::memory_order_acq_rel) == 0u &&
                      value != 0u;
    if (edge) {
        SetEvent(idle_event_);
    }
}

void ArmInterruptChannel::Wake() {
    SetEvent(idle_event_);
}

ArmInterruptChannel::IrqGate ArmInterruptChannel::EvaluateGate() const {
    IrqGate gate;
    gate.level = Level();
    gate.raise = gate.level != 0u && cpu_state_->cpsr.bits.irq_disable == 0u &&
                 cpu_state_->deep_sleep == 0u;
    return gate;
}

bool ArmInterruptChannel::BackOutForIrq(uint32_t guest_pc) {
    if (!EvaluateGate().raise) return false;
    cpu_state_->gprs[ArmGpr::kR15] = guest_pc;
    return true;
}

uint32_t __cdecl ArmInterruptChannel::BackOutForIrqHelper(
    ArmInterruptChannel* channel, uint32_t guest_pc) {
    return channel->BackOutForIrq(guest_pc) ? 1u : 0u;
}

/* ARM DDI 0406C.c B1.8.14: a WFI wake-up event is "a physical IRQ interrupt,
   regardless of the value of the CPSR.I bit". */
void ArmInterruptChannel::WaitForInterrupt() {
    ArmCpuState* state = cpu_state_;
    for (;;) {
        if (state->reset_pending || state->deep_sleep) return;
        const uint32_t exits = std::atomic_ref<uint32_t>(state->chain_exit_request)
                                   .load(std::memory_order_acquire);
        if ((exits & ~(kChainExitIrq | kChainExitFlush)) != 0u) return;
        if (irq_line_.load(std::memory_order_acquire) != 0u) return;
        /* SA-1110 Dev Man §9.5.2.2: with ICCR.DIM = 0 any enabled interrupt, masked
           or unmasked, ends idle mode; the WFI completes and execution resumes. */
        if (idle_wake_line_.load(std::memory_order_acquire) != 0u) return;
        clock_->IdleStep(idle_event_);
    }
}

void __fastcall ArmInterruptChannel::WfiHelper(ArmInterruptChannel* channel) {
    channel->WaitForInterrupt();
}
