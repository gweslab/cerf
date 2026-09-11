#include "iop13xx_cp6.h"
#include "iop13xx_cp6_registers.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../core/steady_time.h"
#include "../../cpu/emulated_memory.h"
#include "../guest_cpu_reset.h"
#include "../../jit/arm/arm_jit.h"
#include "../../jit/arm/block_context.h"
#include "../../jit/arm/cpu_state.h"
#include "../../jit/arm/decoded_insn.h"
#include "../../jit/arm/place_fns.h"
#include "../../jit/x86_emit.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <iterator>

Iop13xxCp6::~Iop13xxCp6() {
    OnShutdown();
}
bool Iop13xxCp6::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::IOP13xx;
}

void Iop13xxCp6::OnReady() {
    {
        std::lock_guard<std::mutex> guard(state_mutex_);
        timer_epoch_us_ = HostSteadyMicros();
        ResetStateLocked(TimerTicks());
    }
    LOG(SocIntc, "IOP13xx CP6 timers: host-monotonic 25 MHz timebase\n");
    timer_thread_ = std::thread(&Iop13xxCp6::TimerLoop, this);
    emu_.Get<GuestCpuReset>().SetCauseLatch(this);

    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
        {
            std::lock_guard<std::mutex> guard(state_mutex_);
            timer_epoch_us_ = HostSteadyMicros();
            ResetStateLocked(TimerTicks());
            NotifyLocked();
        }
        watchdog_reset_requested_.store(false, std::memory_order_release);
    });
}

void Iop13xxCp6::OnShutdown() {
    stop_thread_.store(true, std::memory_order_release);
    if (timer_thread_.joinable()) timer_thread_.join();
}
uint32_t Iop13xxCp6::TimerTicks() const {
    if (timer_epoch_us_ == 0) return 0;
    const uint64_t elapsed_us = HostSteadyMicros() - timer_epoch_us_;
    return static_cast<uint32_t>(elapsed_us * kTimerTicksPerMicrosecond);
}

bool Iop13xxCp6::HasPendingIrqLocked() const {
    for (uint32_t bank = 0; bank < 4; ++bank) {
        if ((pending_[bank] & intctl_[bank] & ~intstr_[bank]) != 0) {
            return true;
        }
    }
    return false;
}

bool Iop13xxCp6::HasPendingFiqLocked() const {
    for (uint32_t bank = 0; bank < 4; ++bank) {
        if ((pending_[bank] & intctl_[bank] & intstr_[bank]) != 0) {
            return true;
        }
    }
    return false;
}

void Iop13xxCp6::ResetStateLocked(uint32_t ticks_now) {
    std::fill(std::begin(intctl_), std::end(intctl_), 0u);
    std::fill(std::begin(intstr_), std::end(intstr_), 0u);
    std::fill(std::begin(pending_), std::end(pending_), 0u);
    std::fill(std::begin(shared_irq_levels_), std::end(shared_irq_levels_), 0u);
    intbase_ = 0;
    intsize_ = 0;
    tisr_ = 0;
    wdtsr_ = 0;
    timer_[0] = Timer{};
    timer_[1] = Timer{};
    watchdog_enabled_ = false;
    watchdog_enable_armed_ = false;
    watchdog_disable_armed_ = false;
    watchdog_elapsed_ticks_ = 0;
    watchdog_last_ticks_ = ticks_now;
}

void Iop13xxCp6::NotifyLocked() {
    if (HasPendingFiqLocked()) {
        emu_.Get<Fatal>().Die("IOP13xx CP6: FIQ source pending");
    }
    auto& jit = emu_.Get<ArmJit>();
    if (HasPendingIrqLocked())
        jit.SetInterruptPending();
    else
        jit.ClearInterruptPending();
}

void Iop13xxCp6::AssertIrq(int source_bit) {
    if (source_bit < 0 || source_bit >= 128) {
        emu_.Get<Fatal>().Die("Iop13xxCp6::AssertIrq: source %d outside 0..127", source_bit);
    }
    std::lock_guard<std::mutex> guard(state_mutex_);
    const uint32_t bank = static_cast<uint32_t>(source_bit) / 32u;
    const uint32_t bit = 1u << (static_cast<uint32_t>(source_bit) & 31u);
    pending_[bank] |= bit;
    NotifyLocked();
}

void Iop13xxCp6::AssertSubIrq(int main_source_bit, int sub_source_bit) {
    emu_.Get<Fatal>().Die("Iop13xxCp6::AssertSubIrq: unsupported sub-source main=%d sub=%d", main_source_bit,
                          sub_source_bit);
}

void Iop13xxCp6::DeAssertIrq(int source_bit) {
    if (source_bit < 0 || source_bit >= 128) return;
    std::lock_guard<std::mutex> guard(state_mutex_);
    const uint32_t bank = static_cast<uint32_t>(source_bit) / 32u;
    const uint32_t bit = 1u << (static_cast<uint32_t>(source_bit) & 31u);
    pending_[bank] &= ~bit;
    NotifyLocked();
}

void Iop13xxCp6::SetSharedIrqLevel(int source_bit, uint32_t contributor_bit, bool asserted) {
    if (source_bit < 0 || source_bit >= 128 || contributor_bit == 0u || !std::has_single_bit(contributor_bit)) {
        emu_.Get<Fatal>().Die("Iop13xxCp6::SetSharedIrqLevel: invalid source %d contributor 0x%08X",
                              source_bit, contributor_bit);
    }
    std::lock_guard<std::mutex> guard(state_mutex_);
    uint32_t& levels = shared_irq_levels_[source_bit];
    if (asserted)
        levels |= contributor_bit;
    else
        levels &= ~contributor_bit;
    const uint32_t bank = static_cast<uint32_t>(source_bit) / 32u;
    const uint32_t bit = 1u << (static_cast<uint32_t>(source_bit) & 31u);
    if (levels != 0u)
        pending_[bank] |= bit;
    else
        pending_[bank] &= ~bit;
    NotifyLocked();
}

void Iop13xxCp6::AdvanceTimerLocked(Timer& timer, uint32_t ticks_now, uint32_t status_bit) {
    if ((timer.control & kTimerEnable) == 0) {
        timer.base_cycles = ticks_now;
        return;
    }
    const uint32_t elapsed_ticks = ticks_now - timer.base_cycles;
    if (elapsed_ticks == 0) return;

    timer.base_cycles += elapsed_ticks;
    if (elapsed_ticks < timer.counter) {
        timer.counter -= elapsed_ticks;
        return;
    }

    if (status_bit != 0) tisr_ |= status_bit;
    if ((timer.control & kTimerReload) != 0 && timer.reload != 0) {
        const uint32_t after_first = elapsed_ticks - timer.counter;
        const uint32_t remainder = after_first % timer.reload;
        timer.counter = remainder == 0 ? timer.reload : timer.reload - remainder;
    } else {
        timer.counter = 0;
        timer.control &= ~kTimerEnable;
    }
}

void Iop13xxCp6::AdvanceTimersLocked(uint32_t ticks_now) {
    AdvanceTimerLocked(timer_[0], ticks_now, 1u);
    AdvanceTimerLocked(timer_[1], ticks_now, 2u);
    AdvanceWatchdogLocked(ticks_now);

    if ((tisr_ & 1u) != 0)
        pending_[0] |= 1u << kTimer0Irq;
    else
        pending_[0] &= ~(1u << kTimer0Irq);
    if ((tisr_ & 2u) != 0)
        pending_[0] |= 1u << kTimer1Irq;
    else
        pending_[0] &= ~(1u << kTimer1Irq);
}

void Iop13xxCp6::LatchWarmReset() {
    std::lock_guard<std::mutex> guard(state_mutex_);
    /* Intel 81341/81342 Developer's Manual, section 10.4.2, Table 448. */
    rcsr_ |= kResetCauseCoreTargeted;
}
void Iop13xxCp6::LatchColdReset() {
    std::lock_guard<std::mutex> guard(state_mutex_);
    /* Intel 81341/81342 Developer's Manual, section 10.4.2, Table 448. */
    rcsr_ = 0;
}
void Iop13xxCp6::LatchWatchdogReset() {
    std::lock_guard<std::mutex> guard(state_mutex_);
    /* Intel 81341/81342 Developer's Manual, section 10.4.2, Table 448. */
    rcsr_ |= kResetCauseWatchdog;
}
void Iop13xxCp6::AdvanceWatchdogLocked(uint32_t ticks_now) {
    const uint32_t elapsed = ticks_now - watchdog_last_ticks_;
    watchdog_last_ticks_ = ticks_now;
    if (!watchdog_enabled_) return;
    watchdog_elapsed_ticks_ += elapsed;
    if (watchdog_elapsed_ticks_ < kWatchdogTimeoutTicks) return;
    if ((wdtsr_ & kWatchdogStatusInternalBusReset) != 0u) {
        watchdog_enabled_ = false;
        rcsr_ |= kResetCauseWatchdog;
        watchdog_reset_requested_.store(true, std::memory_order_release);
        return;
    }
    pending_[0] |= 1u << kWatchdogIrq;
}
void Iop13xxCp6::WriteWatchdogControlLocked(uint32_t value, uint32_t ticks_now) {
    if (value == kWatchdogEnableArm) {
        watchdog_enable_armed_ = true;
        watchdog_disable_armed_ = false;
        return;
    }
    if (value == kWatchdogEnable && watchdog_enable_armed_) {
        watchdog_enabled_ = true;
        watchdog_enable_armed_ = false;
        watchdog_elapsed_ticks_ = 0;
        watchdog_last_ticks_ = ticks_now;
        pending_[0] &= ~(1u << kWatchdogIrq);
        return;
    }
    if (value == kWatchdogDisableArm) {
        watchdog_disable_armed_ = true;
        watchdog_enable_armed_ = false;
        return;
    }
    if (value == kWatchdogDisable && watchdog_disable_armed_) {
        watchdog_enabled_ = false;
        watchdog_disable_armed_ = false;
        pending_[0] &= ~(1u << kWatchdogIrq);
        return;
    }
    if (value == kWatchdogImmediate && watchdog_enabled_ &&
        (wdtsr_ & kWatchdogStatusInternalBusReset) != 0u) {
        watchdog_enabled_ = false;
        rcsr_ |= kResetCauseWatchdog;
        watchdog_reset_requested_.store(true, std::memory_order_release);
        return;
    }
    if (value == 0) {
        watchdog_enable_armed_ = false;
        watchdog_disable_armed_ = false;
        return;
    }
    emu_.Get<Fatal>().Die("IOP13xx CP6 unsupported watchdog control write 0x%08X", value);
}
void Iop13xxCp6::WriteWatchdogStatusLocked(uint32_t value) {
    if ((value & kWatchdogStatusWriteEnable) == 0u) {
        if (value != 0)
            emu_.Get<Fatal>().Die("IOP13xx CP6 locked watchdog status write 0x%08X", value);
        return;
    }
    wdtsr_ = value & ~kWatchdogStatusWriteEnable;
}

void Iop13xxCp6::TimerLoop() {
    auto& freeze = emu_.Get<EmulationFreeze>();
    while (!stop_thread_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::microseconds(100));
        auto frozen = freeze.WorkerSection();
        {
            std::lock_guard<std::mutex> guard(state_mutex_);
            AdvanceTimersLocked(TimerTicks());
            NotifyLocked();
        }
        if (watchdog_reset_requested_.exchange(false, std::memory_order_acq_rel))
            emu_.Get<GuestCpuReset>().WatchdogReset();
    }
}

uint32_t Iop13xxCp6::InterruptVectorLocked() const {
    for (uint32_t bank = 0; bank < 4; ++bank) {
        const uint32_t active = pending_[bank] & intctl_[bank] & ~intstr_[bank];
        if (active == 0) continue;
        const uint32_t source = bank * 32u + std::countr_zero(active);
        const uint32_t shift = intsize_ + 1u;
        const uint32_t vector = intbase_ + (source << shift);
        return vector;
    }
    return 0xFFFFFFFFu;
}

uint32_t Iop13xxCp6::ReadRegisterLocked(uint32_t key, uint32_t cycles_now) {
    AdvanceTimersLocked(cycles_now);
    switch (key) {
    case kCp6ResetCause: return rcsr_;
    case kCp6IntBase: return intbase_;
    case kCp6IntSize: return intsize_;
    case kCp6IntVec: return InterruptVectorLocked();
    case kCp6IntCtl0: return intctl_[0];
    case kCp6IntCtl1: return intctl_[1];
    case kCp6IntCtl2: return intctl_[2];
    case kCp6IntCtl3: return intctl_[3];
    case kCp6Timer0Control: return timer_[0].control;
    case kCp6Timer1Control: return timer_[1].control;
    case kCp6Timer0Counter: return timer_[0].counter;
    case kCp6Timer1Counter: return timer_[1].counter;
    case kCp6Timer0Reload: return timer_[0].reload;
    case kCp6Timer1Reload: return timer_[1].reload;
    case kCp6TimerStatus: return tisr_;
    case kCp6WatchdogCtrl:
        return static_cast<uint32_t>(watchdog_elapsed_ticks_ >= kWatchdogTimeoutTicks
                                         ? 0u
                                         : kWatchdogTimeoutTicks - watchdog_elapsed_ticks_);
    case kCp6WatchdogStat: return wdtsr_;
    default: emu_.Get<Fatal>().Die("IOP13xx CP6 unsupported read key 0x%04X", key);
    }
}

void Iop13xxCp6::WriteRegisterLocked(uint32_t key, uint32_t value, uint32_t cycles_now) {
    AdvanceTimersLocked(cycles_now);
    switch (key) {
    case kCp6IntBase: intbase_ = value; break;
    case kCp6IntSize: intsize_ = value & 3u; break;
    case kCp6IntCtl0: intctl_[0] = value; break;
    case kCp6IntCtl1: intctl_[1] = value; break;
    case kCp6IntCtl2: intctl_[2] = value; break;
    case kCp6IntCtl3: intctl_[3] = value; break;
    case kCp6IntStr0: intstr_[0] = value; break;
    case kCp6IntStr1: intstr_[1] = value; break;
    case kCp6IntStr2: intstr_[2] = value; break;
    case kCp6IntStr3: intstr_[3] = value; break;
    case kCp6Timer0Control:
        timer_[0].control = value;
        timer_[0].base_cycles = cycles_now;
        break;
    case kCp6Timer1Control:
        timer_[1].control = value;
        timer_[1].base_cycles = cycles_now;
        break;
    case kCp6Timer0Counter:
        timer_[0].counter = value;
        timer_[0].base_cycles = cycles_now;
        break;
    case kCp6Timer1Counter:
        timer_[1].counter = value;
        timer_[1].base_cycles = cycles_now;
        break;
    case kCp6Timer0Reload: timer_[0].reload = value; break;
    case kCp6Timer1Reload: timer_[1].reload = value; break;
    case kCp6TimerStatus: tisr_ &= ~value; break;
    case kCp6WatchdogCtrl: WriteWatchdogControlLocked(value, cycles_now); break;
    case kCp6WatchdogStat: WriteWatchdogStatusLocked(value); break;
    default: emu_.Get<Fatal>().Die("IOP13xx CP6 unsupported write key 0x%04X value 0x%08X", key, value);
    }
    AdvanceTimersLocked(cycles_now);
    NotifyLocked();
}

uint32_t __fastcall Iop13xxCp6::ReadHelper(Iop13xxCp6* self, uint32_t key) {
    std::lock_guard<std::mutex> guard(self->state_mutex_);
    return self->ReadRegisterLocked(key, self->TimerTicks());
}

void __fastcall Iop13xxCp6::WriteHelper(Iop13xxCp6* self, uint32_t key, uint32_t value) {
    {
        std::lock_guard<std::mutex> guard(self->state_mutex_);
        self->WriteRegisterLocked(key, value, self->TimerTicks());
    }
    if (self->watchdog_reset_requested_.exchange(false, std::memory_order_acq_rel))
        self->emu_.Get<GuestCpuReset>().WatchdogReset();
}

uint8_t* Iop13xxCp6::EmitRegisterTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx) {
    using namespace x86;
    if (d->cp_opc != 0 || d->cp != 0 || d->rd == 15) {
        return EmitCoprocUnimplementedFatal(cursor, d, ctx);
    }

    const uint32_t key = Iop13xxCp6Key(d->crn, d->crm, d->cp, d->cp_opc);
    const int32_t rd_disp = static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4u);
    EmitMovRegImm32(cursor, kEcx, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(this)));
    EmitMovRegImm32(cursor, kEdx, key);
    if (d->l) {
        EmitCall(cursor, reinterpret_cast<void*>(&Iop13xxCp6::ReadHelper));
        EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
    } else {
        EmitPushBaseDisp32(cursor, kStateReg, rd_disp);
        EmitCall(cursor, reinterpret_cast<void*>(&Iop13xxCp6::WriteHelper));
    }
    return cursor;
}

void Iop13xxCp6::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> guard(state_mutex_);
    AdvanceTimersLocked(TimerTicks());
    w.WriteBytes(intctl_, sizeof(intctl_));
    w.WriteBytes(intstr_, sizeof(intstr_));
    w.WriteBytes(pending_, sizeof(pending_));
    w.WriteBytes(shared_irq_levels_, sizeof(shared_irq_levels_));
    w.Write(intbase_);
    w.Write(intsize_);
    w.Write(tisr_);
    w.Write(rcsr_);
    w.Write(wdtsr_);
    w.Write(watchdog_elapsed_ticks_);
    w.Write<uint8_t>(watchdog_enabled_ ? 1u : 0u);
    w.Write<uint8_t>(watchdog_enable_armed_ ? 1u : 0u);
    w.Write<uint8_t>(watchdog_disable_armed_ ? 1u : 0u);
    w.WriteBytes(timer_, sizeof(timer_));
}

void Iop13xxCp6::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> guard(state_mutex_);
    r.ReadBytes(intctl_, sizeof(intctl_));
    r.ReadBytes(intstr_, sizeof(intstr_));
    r.ReadBytes(pending_, sizeof(pending_));
    r.ReadBytes(shared_irq_levels_, sizeof(shared_irq_levels_));
    r.Read(intbase_);
    r.Read(intsize_);
    r.Read(tisr_);
    r.Read(rcsr_);
    r.Read(wdtsr_);
    r.Read(watchdog_elapsed_ticks_);
    uint8_t enabled = 0;
    uint8_t enable_armed = 0;
    uint8_t disable_armed = 0;
    r.Read(enabled);
    r.Read(enable_armed);
    r.Read(disable_armed);
    watchdog_enabled_ = enabled != 0;
    watchdog_enable_armed_ = enable_armed != 0;
    watchdog_disable_armed_ = disable_armed != 0;
    r.ReadBytes(timer_, sizeof(timer_));
}

void Iop13xxCp6::PostRestoreState() {
    std::lock_guard<std::mutex> guard(state_mutex_);
    const uint32_t ticks = TimerTicks();
    timer_[0].base_cycles = ticks;
    timer_[1].base_cycles = ticks;
    watchdog_last_ticks_ = ticks;
    NotifyLocked();
}

REGISTER_SERVICE_AS(Iop13xxCp6, IrqController);
