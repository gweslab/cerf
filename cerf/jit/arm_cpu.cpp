#include "arm_cpu.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <mutex>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "arm_cpu_exceptions.h"
#include "arm_cpu_ops.h"
#include "arm_jit.h"
#include "arm_mmu.h"
#include "arm_mmu_state.h"
#include "decoded_insn.h"

REGISTER_SERVICE(ArmCpu);

void ArmCpu::OnReady() {
    mmu_ = &emu_.Get<ArmMmu>();
}

void ArmCpu::LateInit(ArmJit* jit) {
    if (jit_ == nullptr) {
        jit_ = jit;
        return;
    }
    if (jit_ != jit) {
        LOG(Caution,
            "ArmCpu::LateInit: re-bound to a different ArmJit instance "
            "(jit_=%p new=%p) — multi-binding is a programming error\n",
            jit_, jit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

void ArmCpu::BankSwitch() {
    ArmCpuBankSwitch(&state_);
}

uint32_t ArmCpu::GetCpsrWithFlags() const {
    return ArmCpuGetCpsrWithFlags(&state_);
}

void ArmCpu::UpdateFlags(uint32_t new_flag_value) {
    ArmCpuUpdateFlags(&state_, new_flag_value);
}

void ArmCpu::UpdateCpsrWithFlags(ArmPsrFull new_psr) {
    ArmCpuUpdateCpsrWithFlags(jit_, &state_, new_psr);
}

void ArmCpu::UpdateCpsr(ArmPsr new_psr) {
    ArmCpuUpdateCpsr(jit_, &state_, new_psr);
}

void* ArmCpu::RaiseUndefinedException(uint32_t inst_ptr) {
    return ArmCpuRaiseUndefinedException(jit_, &state_, inst_ptr);
}

void* ArmCpu::RaiseAbortDataException(uint32_t inst_ptr) {
    return ArmCpuRaiseAbortDataException(jit_, &state_, inst_ptr);
}

void* ArmCpu::RaiseAbortPrefetchException(uint32_t inst_ptr) {
    return ArmCpuRaiseAbortPrefetchException(jit_, &state_, inst_ptr);
}

void* ArmCpu::RaiseIrqException(uint32_t inst_ptr) {
    return ArmCpuRaiseIrqException(jit_, &state_, inst_ptr);
}

void* ArmCpu::RaiseSoftwareInterruptException(uint32_t inst_ptr) {
    return ArmCpuRaiseSoftwareInterruptException(jit_, &state_, inst_ptr);
}

void ArmCpu::SetInitialStackPointer(uint32_t sp) {
    state_.gprs_svc[ArmGpr::kR13Svc] = sp;
}

void ArmCpu::RaiseResetException(uint32_t initial_pc) {
    initial_pc_ = initial_pc;
    DoRaiseReset();
}

void ArmCpu::RaiseResetException() {
    DoRaiseReset();
}

bool ArmCpu::AreInterruptsEnabled() const {
    return !state_.cpsr.bits.irq_disable || !state_.cpsr.bits.fiq_disable;
}

void ArmCpu::DoRaiseReset() {
    state_.reset_pending = 0;
    state_.gprs_svc[ArmGpr::kR14Svc] = state_.gprs[ArmGpr::kR15];
    state_.spsr_svc = ArmCpuGetCpsrWithFlags(&state_);

    state_.cpsr.bits.mode        = ArmMode::kSupervisor;
    state_.cpsr.bits.thumb_mode  = 0;
    state_.cpsr.bits.fiq_disable = 1;

    {
        std::lock_guard<std::mutex> guard(jit_->InterruptLock());
        state_.cpsr.bits.irq_disable = 1;
        jit_->UpdateInterruptOnPoll();
    }

    state_.gprs[ArmGpr::kR15] = initial_pc_;

    ArmMmuState* mmu_state = mmu_->State();
    mmu_state->control_register.word = 0;
    mmu_state->process_id            = 0;
}

uint32_t* ArmCpu::GetUserModeRegisterAddress(int reg_num) {
    /* R0..R12 and R15 never bank-switch — always come from gprs[]. */
    if (reg_num < 13 || reg_num > 14) {
        return &state_.gprs[reg_num];
    }

    /* R13/R14: bank-switched on every privileged-mode entry. In
       User/System mode, gprs[13/14] already hold the user-view
       values. In IRQ/SVC/ABT/UND, the bank-switch on mode entry
       stashed the user-view R13/R14 into gprs_<mode>[0/1]. */
    const int bank_idx = reg_num - 13;
    switch (state_.cpsr.bits.mode) {
    case ArmMode::kUser:
    case ArmMode::kSystem:
        return &state_.gprs[reg_num];

    case ArmMode::kSupervisor: return &state_.gprs_svc[bank_idx];
    case ArmMode::kIrq:        return &state_.gprs_irq[bank_idx];
    case ArmMode::kAbort:      return &state_.gprs_abt[bank_idx];
    case ArmMode::kUndefined:  return &state_.gprs_und[bank_idx];

    case ArmMode::kFiq:
        LOG(Caution, "ArmCpu::GetUserModeRegisterAddress: FIQ mode not modelled\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);

    default:
        LOG(Caution, "ArmCpu::GetUserModeRegisterAddress: invalid mode 0x%X\n",
            state_.cpsr.bits.mode);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

void* __cdecl ArmCpu::RaiseUndefinedExceptionHelper(ArmCpu* cpu, uint32_t pc) {
    return cpu->RaiseUndefinedException(pc);
}

void* __cdecl ArmCpu::RaiseAbortPrefetchExceptionHelper(ArmCpu* cpu, uint32_t pc) {
    return cpu->RaiseAbortPrefetchException(pc);
}

void* __cdecl ArmCpu::RaiseSoftwareInterruptExceptionHelper(ArmCpu* cpu, uint32_t pc) {
    return cpu->RaiseSoftwareInterruptException(pc);
}

void __cdecl ArmCpu::PerformSyscallHelper() {
    LOG(Caution, "ArmCpu::PerformSyscallHelper: SYSCALL on a board with no syscall mechanism\n");
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void __cdecl ArmCpu::PowerDownHelper() {
    LOG(Boot, "ArmCpu: PowerDownHelper invoked (guest entered suspend mode); exiting\n");
    CerfFatalExit(0);
}

uint32_t ArmCpu::ComputePSRMaskValue(int field_mask) {
    uint32_t mask = 0;
    if (field_mask & 1) mask |= 0xFFu;
    if (field_mask & 2) mask |= 0xFF00u;
    if (field_mask & 4) mask |= 0xFF0000u;
    if (field_mask & 8) mask |= 0xFF000000u;
    return mask;
}

uint8_t ArmCpu::GetX86FlagsMask(const DecodedInsn* d) {
    constexpr uint8_t kZ = static_cast<uint8_t>(kX86FlagZf);
    constexpr uint8_t kN = static_cast<uint8_t>(kX86FlagNf);
    constexpr uint8_t kC = static_cast<uint8_t>(kX86FlagCf);

    switch (d->flags_set) {
    case kFlagsAll:                         return 0xFFu;
    case kFlagN | kFlagZ | kFlagC:          return kZ | kC | kN;
    case kFlagZ:
    case kFlagZ | kFlagV:                   return kZ;
    case kFlagN:
    case kFlagN | kFlagV:                   return kN;
    case kFlagC:
    case kFlagC | kFlagV:                   return kC;
    case kFlagZ | kFlagC:
    case kFlagZ | kFlagC | kFlagV:          return kZ | kC;
    case kFlagN | kFlagZ:
    case kFlagN | kFlagZ | kFlagV:          return kZ | kN;
    case kFlagV:
    case kFlagsNone:                        return 0;
    case kFlagN | kFlagC:
    case kFlagN | kFlagC | kFlagV:          return kN | kC;
    default:
        LOG(Caution, "ArmCpu::GetX86FlagsMask: unhandled flags_set=0x%X\n",
            d->flags_set);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

uint32_t __cdecl ArmCpu::UpdatePSRMaskHelper(uint32_t current_psr,
                                             uint32_t new_psr,
                                             uint32_t mask,
                                             ArmCpu*  cpu) {
    if (cpu->state_.cpsr.bits.mode == ArmMode::kUser) {
        /* Only flag bits writable from user mode. */
        mask &= 0xFF000000u;
    }
    return (current_psr & ~mask) | (new_psr & mask);
}

uint32_t __cdecl ArmCpu::GetCpsrWithFlagsHelper(ArmCpu* cpu) {
    return ArmCpuGetCpsrWithFlags(&cpu->state_);
}

void __cdecl ArmCpu::UpdateFlagsHelper(ArmCpu* cpu, uint32_t new_flags) {
    ArmCpuUpdateFlags(&cpu->state_, new_flags);
}

void __cdecl ArmCpu::UpdateNzcvOnlyHelper(ArmCpu* cpu, uint32_t new_flags) {
    ArmCpuUpdateNzcvOnly(&cpu->state_, new_flags);
}

void __cdecl ArmCpu::UpdateCpsrWithFlagsHelper(ArmCpu*  cpu,
                                               uint32_t new_psr_word) {
    ArmPsrFull psr;
    psr.word = new_psr_word;
    ArmCpuUpdateCpsrWithFlags(cpu->jit_, &cpu->state_, psr);
}
