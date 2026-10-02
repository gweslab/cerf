#include "iop13xx_cp6.h"
#include "iop13xx_cp6_registers.h"
#include "iop13xx_timers.h"

#include "../../boards/board_context.h"
#include "iop13xx_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"
#include "../guest_cpu_reset.h"
#include "../../jit/arm/arm_jit.h"
#include "../../jit/arm/block_context.h"
#include "../../jit/arm/cpu_state.h"
#include "../../jit/arm/decoded_insn.h"
#include "../../jit/arm/place_fns.h"
#include "../../jit/x86_emit.h"
#include "../../state/state_stream.h"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <iterator>

bool Iop13xxCp6::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Iop13xx;
}

void Iop13xxCp6::OnReady() {
    timers_ = &emu_.Get<Iop13xxTimers>();
    {
        std::lock_guard<std::mutex> guard(state_mutex_);
        ResetStateLocked();
    }
    emu_.Get<GuestCpuReset>().SetCauseLatch(this);

    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
        std::lock_guard<std::mutex> guard(state_mutex_);
        ResetStateLocked();
        NotifyLocked();
    });
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

void Iop13xxCp6::ResetStateLocked() {
    std::fill(std::begin(intctl_), std::end(intctl_), 0u);
    std::fill(std::begin(intstr_), std::end(intstr_), 0u);
    std::fill(std::begin(pending_), std::end(pending_), 0u);
    std::fill(std::begin(shared_irq_levels_), std::end(shared_irq_levels_), 0u);
    intbase_ = 0;
    intsize_ = 0;
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

uint32_t Iop13xxCp6::ReadRegisterLocked(uint32_t key) {
    switch (key) {
    case kCp6ResetCause: return rcsr_;
    case kCp6IntBase: return intbase_;
    case kCp6IntSize: return intsize_;
    case kCp6IntVec: return InterruptVectorLocked();
    case kCp6IntCtl0: return intctl_[0];
    case kCp6IntCtl1: return intctl_[1];
    case kCp6IntCtl2: return intctl_[2];
    case kCp6IntCtl3: return intctl_[3];
    default: emu_.Get<Fatal>().Die("IOP13xx CP6 unsupported read key 0x%04X", key);
    }
}

void Iop13xxCp6::WriteRegisterLocked(uint32_t key, uint32_t value) {
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
    default: emu_.Get<Fatal>().Die("IOP13xx CP6 unsupported write key 0x%04X value 0x%08X", key, value);
    }
    NotifyLocked();
}

uint32_t __fastcall Iop13xxCp6::ReadHelper(Iop13xxCp6* self, uint32_t key) {
    if (Iop13xxTimers::IsTimerKey(key)) return self->timers_->Read(key);
    std::lock_guard<std::mutex> guard(self->state_mutex_);
    return self->ReadRegisterLocked(key);
}

void __fastcall Iop13xxCp6::WriteHelper(Iop13xxCp6* self, uint32_t key, uint32_t value) {
    if (Iop13xxTimers::IsTimerKey(key)) {
        self->timers_->Write(key, value);
        return;
    }
    std::lock_guard<std::mutex> guard(self->state_mutex_);
    self->WriteRegisterLocked(key, value);
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
    {
        std::lock_guard<std::mutex> guard(state_mutex_);
        w.WriteBytes("intctl", intctl_, sizeof(intctl_));
        w.WriteBytes("intstr", intstr_, sizeof(intstr_));
        w.WriteBytes("pending", pending_, sizeof(pending_));
        w.WriteBytes("shared_irq_levels", shared_irq_levels_, sizeof(shared_irq_levels_));
        w.Write("intbase", intbase_);
        w.Write("intsize", intsize_);
        w.Write("rcsr", rcsr_);
    }
    timers_->SaveState(w);
}

void Iop13xxCp6::RestoreState(StateReader& r) {
    {
        std::lock_guard<std::mutex> guard(state_mutex_);
        r.ReadBytes("intctl", intctl_, sizeof(intctl_));
        r.ReadBytes("intstr", intstr_, sizeof(intstr_));
        r.ReadBytes("pending", pending_, sizeof(pending_));
        r.ReadBytes("shared_irq_levels", shared_irq_levels_, sizeof(shared_irq_levels_));
        r.Read("intbase", intbase_);
        r.Read("intsize", intsize_);
        r.Read("rcsr", rcsr_);
    }
    timers_->RestoreState(r);
}

void Iop13xxCp6::PostRestoreState() {
    {
        std::lock_guard<std::mutex> guard(state_mutex_);
        NotifyLocked();
    }
    timers_->PostRestore();
}

REGISTER_SERVICE_AS(Iop13xxCp6, IrqController);
