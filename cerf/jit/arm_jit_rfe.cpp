#include "arm_jit.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "arm_cpu.h"
#include "arm_cpu_ops.h"
#include "arm_jit_runtime.h"
#include "arm_mmu.h"
#include "cpu_state.h"

uint32_t __fastcall ArmJit::RfeHelper(uint32_t rn_value,
                                      uint32_t encoded,
                                      ArmJit*  jit) {
    const bool     p_bit = (encoded & 0x80u) != 0u;
    const bool     u_bit = (encoded & 0x40u) != 0u;
    const bool     w_bit = (encoded & 0x20u) != 0u;
    const uint32_t rn    = encoded & 0x1Fu;

    /* ddi0406c B9.3.13 RFE pseudocode:
         address = if increment then R[n] else R[n]-8;
         if wordhigher then address = address+4; */
    uint32_t address = u_bit ? rn_value : (rn_value - 8u);
    if (p_bit == u_bit) {
        address += 4u;
    }

    ArmCpuState* state = jit->CpuState();

    uint8_t* host_pc_ptr = jit->mmu_->TranslateRead(state, address);
    if (!host_pc_ptr) {
        LOG(Caution, "RfeHelper: TranslateRead failed for VA 0x%08X (new_pc slot) "
                      "— RFE from non-RAM or aborted load not supported\n", address);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    uint32_t new_pc = *reinterpret_cast<uint32_t*>(host_pc_ptr);

    uint8_t* host_cpsr_ptr = jit->mmu_->TranslateRead(state, address + 4u);
    if (!host_cpsr_ptr) {
        LOG(Caution, "RfeHelper: TranslateRead failed for VA 0x%08X (new_cpsr slot)"
                      " — RFE from non-RAM or aborted load not supported\n",
                      address + 4u);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    uint32_t new_cpsr = *reinterpret_cast<uint32_t*>(host_cpsr_ptr);

    /* Writeback BEFORE the CPSR change so it lands in the OLD mode's
       bank (ddi0406c B9.3.13 pseudocode ordering). */
    if (w_bit) {
        state->gprs[rn] = u_bit ? (rn_value + 8u) : (rn_value - 8u);
    }

    /* CPSRWriteByInstr(spsr_value, '1111', TRUE) — full CPSR overwrite
       including mode + flags + T. UpdateCpsrWithFlags handles the bank
       swap + IRQ-poll. */
    ArmPsrFull new_psr;
    new_psr.word = new_cpsr;
    ArmCpuUpdateCpsrWithFlags(jit, state, new_psr);

    /* BranchWritePC — bits[1:0] masked per the new ISA. */
    if (state->cpsr.bits.thumb_mode) {
        new_pc &= ~1u;
    } else {
        new_pc &= ~3u;
    }
    return new_pc;
}
