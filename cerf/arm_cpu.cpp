/* ARM CPU core: condition checking, barrel shifter, run loop, stepping */
#include "arm_cpu.h"
#include <cstdlib>

bool ArmCpu::CheckCondition(uint32_t cond) const {
    switch (cond) {
    case COND_EQ: return GetZ();
    case COND_NE: return !GetZ();
    case COND_CS: return GetC();
    case COND_CC: return !GetC();
    case COND_MI: return GetN();
    case COND_PL: return !GetN();
    case COND_VS: return GetV();
    case COND_VC: return !GetV();
    case COND_HI: return GetC() && !GetZ();
    case COND_LS: return !GetC() || GetZ();
    case COND_GE: return GetN() == GetV();
    case COND_LT: return GetN() != GetV();
    case COND_GT: return !GetZ() && (GetN() == GetV());
    case COND_LE: return GetZ() || (GetN() != GetV());
    case COND_AL: return true;
    case COND_NV: return true; /* In ARMv5+, NV is used for unconditional */
    }
    return false;
}

uint32_t ArmCpu::BarrelShift(uint32_t val, uint32_t shift_type, uint32_t shift_amount, bool& carry_out, bool reg_shift) {
    carry_out = GetC();

    if (shift_amount == 0 && !reg_shift) {
        /* Special cases when shift amount is 0 in immediate form */
        switch (shift_type) {
        case 0: /* LSL #0 -> no shift */
            return val;
        case 1: /* LSR #0 -> LSR #32 */
            carry_out = (val >> 31) & 1;
            return 0;
        case 2: /* ASR #0 -> ASR #32 */
            carry_out = (val >> 31) & 1;
            return (int32_t)val >> 31;
        case 3: /* ROR #0 -> RRX (rotate right extended) */
            carry_out = val & 1;
            return (GetC() ? 0x80000000 : 0) | (val >> 1);
        }
    }

    if (reg_shift && shift_amount == 0) return val;

    switch (shift_type) {
    case 0: /* LSL */
        if (shift_amount >= 32) {
            carry_out = (shift_amount == 32) ? (val & 1) : 0;
            return 0;
        }
        carry_out = (val >> (32 - shift_amount)) & 1;
        return val << shift_amount;

    case 1: /* LSR */
        if (shift_amount >= 32) {
            carry_out = (shift_amount == 32) ? ((val >> 31) & 1) : 0;
            return 0;
        }
        carry_out = (val >> (shift_amount - 1)) & 1;
        return val >> shift_amount;

    case 2: /* ASR */
        if (shift_amount >= 32) {
            carry_out = (val >> 31) & 1;
            return (int32_t)val >> 31;
        }
        carry_out = (val >> (shift_amount - 1)) & 1;
        return (int32_t)val >> shift_amount;

    case 3: /* ROR */
        shift_amount &= 31;
        if (shift_amount == 0) return val;
        val = (val >> shift_amount) | (val << (32 - shift_amount));
        carry_out = (val >> 31) & 1;
        return val;
    }
    return val;
}

void ArmCpu::Run(uint64_t max_insns) {
    while (!halted) {
        Step();
        if (max_insns && insn_count >= max_insns) break;
    }
}

/* Ring buffer for last N instructions (for crash debugging) */
struct TraceEntry {
    uint32_t pc;
    uint32_t insn;
    bool thumb;
    uint32_t r0, r1, lr;
};
static const int TRACE_SIZE = 1024;
static TraceEntry trace_buf[TRACE_SIZE];
static int trace_idx = 0;

void ArmCpu::Step() {
    if (halted) return;

    if (IsThumb()) {
        uint32_t pc = r[REG_PC];
        uint16_t insn = mem->Read16(pc);

        trace_buf[trace_idx % TRACE_SIZE] = { pc, insn, true, r[0], r[1], r[REG_LR] };
        trace_idx++;

        r[REG_PC] = pc + 2;
        ExecuteThumb(insn);
    } else {
        uint32_t pc = r[REG_PC];
        uint32_t insn = mem->Read32(pc);

        trace_buf[trace_idx % TRACE_SIZE] = { pc, insn, false, r[0], r[1], r[REG_LR] };
        trace_idx++;

        if (trace) {
            printf("[TRACE] %08X: %08X  R0=%08X R1=%08X LR=%08X\n",
                   pc, insn, r[0], r[1], r[REG_LR]);
        }

        r[REG_PC] = pc + 4;
        ExecuteArm(insn);
    }
    insn_count++;

    /* Detect execution from sentinel return addresses */
    uint32_t current_pc = r[REG_PC];
    if (!halted && (current_pc == 0xCAFEC000)) {
        /* Callback return sentinel - don't halt, let the callback executor handle it */
        return;
    }
    if (!halted && (current_pc == 0xDEADDEAD || current_pc == 0xDEADDEAC)) {
        printf("\n[EMU] Hit sentinel return address - program returned from entry point\n");
        printf("[EMU]   Return code (R0) = %d (0x%08X)\n", r[0], r[0]);
        halted = true;
        halt_code = r[0];
    }

    /* Detect execution from unmapped memory */
    if (!halted && !mem->Translate(current_pc)) {
        printf("\n[EMU] FAULT: PC at unmapped address 0x%08X!\n", current_pc);
        printf("[EMU]   R0=%08X R1=%08X LR=%08X SP=%08X\n",
               r[0], r[1], r[REG_LR], r[REG_SP]);
        halted = true;
        halt_code = 4;
    }

    /* Detect execution from stack/non-code memory */
    if (!halted && current_pc >= 0x000F0000 && current_pc < 0x00100000) {
        printf("\n[EMU] WARNING: Execution entered stack area at PC=0x%08X!\n", current_pc);
        printf("[EMU]   Previous instruction #%llu at %08X\n", insn_count - 1,
               trace_buf[(trace_idx - 2) % TRACE_SIZE].pc);
        printf("[EMU]   R0=%08X R1=%08X LR=%08X SP=%08X\n",
               r[0], r[1], r[REG_LR], r[REG_SP]);
        /* Dump last 32 instructions */
        int count = (trace_idx > 64) ? 64 : trace_idx;
        int start = trace_idx - count;
        printf("--- Last %d instructions ---\n", count);
        for (int i = start; i < trace_idx; i++) {
            auto& e = trace_buf[i % TRACE_SIZE];
            if (e.thumb) {
                printf("  [%08X] %04X (Thumb) R0=%08X R1=%08X LR=%08X\n",
                       e.pc, e.insn, e.r0, e.r1, e.lr);
            } else {
                printf("  [%08X] %08X (ARM)   R0=%08X R1=%08X LR=%08X\n",
                       e.pc, e.insn, e.r0, e.r1, e.lr);
            }
        }
        halted = true;
        halt_code = 3;
    }

    /* Dump trace on halt */
    if (halted) {
        int count = (trace_idx > 64) ? 64 : trace_idx;
        int start = trace_idx - count;
        printf("\n--- Last %d instructions before halt ---\n", count);
        for (int i = start; i < trace_idx; i++) {
            auto& e = trace_buf[i % TRACE_SIZE];
            if (e.thumb) {
                printf("  [%08X] %04X (Thumb) R0=%08X R1=%08X LR=%08X\n",
                       e.pc, e.insn, e.r0, e.r1, e.lr);
            } else {
                printf("  [%08X] %08X (ARM)   R0=%08X R1=%08X LR=%08X\n",
                       e.pc, e.insn, e.r0, e.r1, e.lr);
            }
        }
    }
}
