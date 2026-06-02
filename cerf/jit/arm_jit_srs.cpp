#include "arm_jit.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "arm_cpu.h"
#include "arm_mmu.h"
#include "cpu_state.h"

namespace {

/* Resolve a target ARM mode's banked R13 against CERF's banking model:
   live gprs[13] holds the current mode's R13; gprs_<mode>[0] holds the
   parked R13 of <mode> WHEN not in <mode>, and holds the User-view R13
   when in <mode>. */
uint32_t* GetBankedR13(ArmCpuState* state, uint32_t target_mode) {
    const uint32_t current_mode = state->cpsr.bits.mode;
    if (current_mode == target_mode) {
        return &state->gprs[ArmGpr::kR13];
    }

    switch (target_mode) {
    case ArmMode::kSupervisor: return &state->gprs_svc[ArmGpr::kR13Svc];
    case ArmMode::kAbort:      return &state->gprs_abt[ArmGpr::kR13Abt];
    case ArmMode::kIrq:        return &state->gprs_irq[ArmGpr::kR13Irq];
    case ArmMode::kUndefined:  return &state->gprs_und[ArmGpr::kR13Und];

    case ArmMode::kUser:
    case ArmMode::kSystem:
        /* User/System R13 — parked in the current privileged mode's
           bank slot per CERF's banking model. */
        switch (current_mode) {
        case ArmMode::kSupervisor: return &state->gprs_svc[ArmGpr::kR13Svc];
        case ArmMode::kAbort:      return &state->gprs_abt[ArmGpr::kR13Abt];
        case ArmMode::kIrq:        return &state->gprs_irq[ArmGpr::kR13Irq];
        case ArmMode::kUndefined:  return &state->gprs_und[ArmGpr::kR13Und];
        default:                   return nullptr;
        }

    default:
        return nullptr;
    }
}

}  /* namespace */

void __fastcall ArmJit::SrsHelper(uint32_t encoded,
                                  ArmJit*  jit,
                                  uint32_t guest_pc) {
    const bool     p_bit       = (encoded & 0x80u) != 0u;
    const bool     u_bit       = (encoded & 0x40u) != 0u;
    const bool     w_bit       = (encoded & 0x20u) != 0u;
    const uint32_t target_mode = encoded & 0x1Fu;

    ArmCpuState*   state        = jit->CpuState();
    const uint32_t current_mode = state->cpsr.bits.mode;

    if (current_mode == ArmMode::kUser || current_mode == ArmMode::kSystem) {
        LOG(Caution, "SrsHelper pc=0x%08X: executed in User/System mode "
                      "(CPSR.M=0x%X) — UNPREDICTABLE\n",
                      guest_pc, current_mode);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    /* ddi0406c B9.3.16: target Hyp (0x1A) is UNPREDICTABLE. */
    if (target_mode == 0x1Au) {
        LOG(Caution, "SrsHelper pc=0x%08X: target Hyp mode (0x1A) — UNPREDICTABLE\n",
            guest_pc);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    uint32_t* base_ptr = GetBankedR13(state, target_mode);
    if (!base_ptr) {
        LOG(Caution, "SrsHelper pc=0x%08X: target mode 0x%X unsupported "
                      "(FIQ unmodelled or invalid mode field)\n",
                      guest_pc, target_mode);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    const uint32_t base    = *base_ptr;
    uint32_t       address = u_bit ? base : (base - 8u);
    if (p_bit == u_bit) {
        address += 4u;
    }

    uint8_t* host_lr = jit->mmu_->TranslateWrite(state, address);
    if (!host_lr) {
        LOG(Caution, "SrsHelper pc=0x%08X: TranslateWrite failed for LR slot "
                      "VA 0x%08X — SRS to non-RAM or aborted store not supported\n",
                      guest_pc, address);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    *reinterpret_cast<uint32_t*>(host_lr) = state->gprs[ArmGpr::kR14];

    uint8_t* host_spsr = jit->mmu_->TranslateWrite(state, address + 4u);
    if (!host_spsr) {
        LOG(Caution, "SrsHelper pc=0x%08X: TranslateWrite failed for SPSR slot "
                      "VA 0x%08X — SRS to non-RAM or aborted store not supported\n",
                      guest_pc, address + 4u);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    *reinterpret_cast<uint32_t*>(host_spsr) = state->spsr.word;

    if (w_bit) {
        *base_ptr = u_bit ? (base + 8u) : (base - 8u);
    }
}
