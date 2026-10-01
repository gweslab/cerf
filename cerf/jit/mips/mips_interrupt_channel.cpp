#include "mips_interrupt_channel.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../cpu/mips_processor_config.h"
#include "../guest_cycle_clock.h"
#include "../host_request_channel.h"
#include "mips_cpu.h"
#include "mips_cpu_state.h"

REGISTER_SERVICE(MipsInterruptChannel);

MipsInterruptChannel::~MipsInterruptChannel() {
    if (idle_event_) {
        CloseHandle(idle_event_);
        idle_event_ = nullptr;
    }
}

void MipsInterruptChannel::OnReady() {
    cpu_state_      = emu_.Get<MipsCpu>().State();
    device_ip_mask_ = emu_.Get<MipsProcessorConfig>().DeviceIpMask();
    standby_lines_  = kMipsCauseIpMask & ~device_ip_mask_;
    clock_          = &emu_.Get<GuestCycleClock>();
    host_requests_  = &emu_.Get<HostRequestChannel>();

    idle_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!idle_event_) {
        LOG(Caution, "MipsInterruptChannel: CreateEventW(idle_event) failed "
                "gle=%lu\n", GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

void MipsInterruptChannel::SignalIdleWake() {
    if (idle_event_) SetEvent(idle_event_);
}

void MipsInterruptChannel::SetExternalInterruptLevel(uint32_t ip_mask) {
    const uint32_t prev = external_ip_.exchange(ip_mask, std::memory_order_acq_rel);
    if (ip_mask & ~prev) SignalIdleWake();
}

void MipsInterruptChannel::RequestDispatch(uint32_t bits) {
    const uint32_t prev = dispatch_request_.fetch_or(bits, std::memory_order_acq_rel);
    if (bits & ~prev) SignalIdleWake();
}

void MipsInterruptChannel::SetResetRequest(bool pending) {
    if (pending) dispatch_request_.fetch_or(kDispatchReset, std::memory_order_acq_rel);
    else         dispatch_request_.fetch_and(~kDispatchReset, std::memory_order_acq_rel);
}

uint32_t MipsInterruptChannel::TakeDispatchRequests() {
    return dispatch_request_.exchange(0u, std::memory_order_acq_rel);
}

void MipsInterruptChannel::SetHostExit(bool requested) {
    host_exit_.store(requested, std::memory_order_release);
    if (requested) SignalIdleWake();
}

bool MipsInterruptChannel::TakeHostRequest() {
    return (dispatch_request_.fetch_and(~kDispatchHostClock, std::memory_order_acq_rel) &
            kDispatchHostClock) != 0u;
}

void MipsInterruptChannel::RegisterSuspendListener(std::function<void()> fn) {
    suspend_listeners_.push_back(std::move(fn));
}

void MipsInterruptChannel::RunSuspendListeners() {
    for (auto& fn : suspend_listeners_) fn();
}

uint64_t MipsInterruptChannel::CyclesOutsideSuspend() {
    if (suspended_) return suspend_start_cycle_ - suspended_cycles_;
    return clock_->Cycles() - suspended_cycles_;
}

/* Standby ends on an interrupt request its IM bit does not mask (VR4121 UM 10.2-10.4); Suspend
   ends on the ICU's int_all (VR4131 UM 11.1 p187, VR4102 UM Table 15-3 text p326). */
bool MipsInterruptChannel::InterruptPending(uint32_t idle) const {
    const uint32_t level = external_ip_.load(std::memory_order_acquire) & device_ip_mask_;
    if (idle != MipsIdle::kStandby) return level != 0u;
    const uint32_t lines = level | (cpu_state_->cp0_cause & standby_lines_);
    return (lines & cpu_state_->cp0_status & kMipsCauseIpMask) != 0u;
}

bool MipsInterruptChannel::WaitForInterrupt(uint32_t idle) {
    const MipsCpuState& s = *cpu_state_;
    bool woke = true;
    for (;;) {
        if (ResetRequested() || s.deep_sleep) break;
        if (host_exit_.load(std::memory_order_acquire)) {
            woke = false;
            break;
        }
        if (TakeHostRequest()) host_requests_->ServiceRequests();
        if (InterruptPending(idle)) break;
        clock_->IdleStep(idle_event_);
    }
    clock_->ExitIdle();
    return woke;
}

void MipsInterruptChannel::EnterIdle(const char* insn, uint32_t next_pc) {
    MipsCpuState& s = *cpu_state_;
    if (s.branch_state != MipsBranch::kNone) {
        emu_.Get<Fatal>().Die("MipsInterruptChannel: %s at 0x%08X in a branch delay slot is not "
                              "modeled", insn, s.pc);
    }
    s.pc = next_pc;
}

/* Suspend stops TClock and every internal peripheral clock but the RTC/ICU/PMU ones, while
   the timer/interrupt clocks and MasterOut run (VR4102 UM Table 15-3 p326, VR4121 UM
   8.4.1(3)). */
void MipsInterruptChannel::OpenSuspendSpan() {
    suspend_start_cycle_ = clock_->Cycles();
    suspended_           = true;
    RunSuspendListeners();
}

void MipsInterruptChannel::CloseSuspendSpan() {
    suspended_cycles_ += clock_->Cycles() - suspend_start_cycle_;
    suspended_         = false;
    RunSuspendListeners();
}

void __fastcall MipsInterruptChannel::StandbyInsnHelper(MipsInterruptChannel* channel,
                                                        uint32_t next_pc) {
    channel->EnterIdle("STANDBY", next_pc);
    if (!channel->WaitForInterrupt(MipsIdle::kStandby)) {
        channel->cpu_state_->idle_wait = MipsIdle::kStandby;
    }
}

void __fastcall MipsInterruptChannel::SuspendInsnHelper(MipsInterruptChannel* channel,
                                                        uint32_t next_pc) {
    channel->EnterIdle("SUSPEND", next_pc);
    channel->OpenSuspendSpan();
    if (channel->WaitForInterrupt(MipsIdle::kSuspend)) {
        channel->CloseSuspendSpan();
    } else {
        channel->cpu_state_->idle_wait = MipsIdle::kSuspend;
    }
}

bool MipsInterruptChannel::ResumeIdle() {
    MipsCpuState& s = *cpu_state_;
    if (!WaitForInterrupt(s.idle_wait)) return false;
    if (s.idle_wait == MipsIdle::kSuspend) CloseSuspendSpan();
    s.idle_wait = MipsIdle::kNone;
    return true;
}

/* STOPCPU "will cause the clock to the CPU core to be disabled"; "The bit is cleared whenever an
   enabled interrupt is set" (TMPR3911 §12.3.1 p12-13). */
void MipsInterruptChannel::StopCpuAfterAccess() {
    MipsCpuState& s = *cpu_state_;
    if (s.isa_mode != 0u) {
        emu_.Get<Fatal>().Die("MipsInterruptChannel: STOPCPU from MIPS16 code at 0x%08X is not "
                              "modeled", s.pc);
    }
    EnterIdle("STOPCPU", s.pc + 4u);
    s.idle_wait = MipsIdle::kStopCpu;
}

void MipsInterruptChannel::OnCpuStateRestored() {
    suspended_        = false;
    suspended_cycles_ = 0;
    const MipsCpuState& s = *cpu_state_;
    if (s.idle_wait == MipsIdle::kSuspend) {
        suspend_start_cycle_ = clock_->Cycles();
        suspended_           = true;
    }
}
