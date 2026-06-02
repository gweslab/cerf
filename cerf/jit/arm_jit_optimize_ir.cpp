#include "arm_jit.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstring>
#include <intrin.h>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../cpu/arm_processor_config.h"
#include "../cpu/emulated_memory.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "arm_cpu_exceptions.h"
#include "arm_cpu_ops.h"
#include "arm_jit_runtime.h"
#include "arm_mmu.h"
#include "arm_mmu_state.h"
#include "place_fns.h"
#include "x86_emit.h"

int ArmJit::JitOptimizeIR() {
    /* Returned at the end; LocateEntrypoints does the marking +
       FlagsNeeded/FlagsSet computation pass. */
    int entrypoint_count = LocateEntrypoints();

    /* Sentinel for the two-stage DCleanCache loop optimization
       (inner loop sets this when its pattern matches, outer loop
       checks for it). uint32_t -1 means "no inner-loop pattern
       seen yet". */
    uint32_t dcache_optimization_slot = static_cast<uint32_t>(-1);

    for (uint32_t i = 0; i < block_ctx_.num_insns; ++i) {
        DecodedInsn& insn = block_ctx_.insns[i];

        /* Single-instruction optimization: "LDR Rd, [PC + immediate]"
           where the source PA is in read-only memory — sneak a peek
           and inline the value as a MOV Rd, immediate. */
        if (insn.place_fn == &PlaceSingleDataTransfer &&
            insn.rn == ArmGpr::kR15 &&
            insn.p &&
            insn.b == 0 &&
            insn.w == 0 &&
            insn.l &&
            insn.i == 0) {
            const uint32_t addr = ApplyFcseFold(*mmu_->State(), insn.reserved3);

            if (mmu_->State()->control_register.bits.m && (addr & 3u) == 0u) {
                uint8_t* host_read_addr =
                    mmu_->TranslateRead(cpu_->State(), addr);
                if (host_read_addr &&
                    mmu_->TranslateReadWrite(cpu_->State(), addr) == nullptr) {
                    uint32_t value;
                    std::memcpy(&value, host_read_addr, sizeof(value));

                    insn.place_fn  = &PlaceDataProcessing;
                    insn.opcode    = 13;  /* MOV */
                    insn.s         = 0;
                    insn.i         = 1;
                    insn.reserved3 = value;
                }
            }
        }

        if (i < 1) {
            continue;
        }

        /* From here on, peephole optimizations that look at the
           previous instruction (i-1) and the current. */
        DecodedInsn& prev = block_ctx_.insns[i - 1];

        if (prev.entry_point == insn.entry_point &&
            prev.cond == insn.cond &&
            prev.place_fn == &PlaceSingleDataTransfer &&
            insn.place_fn == &PlaceSingleDataTransfer &&
            prev.l == 0 &&
            insn.l == 1 &&
            prev.rn == ArmGpr::kR13 &&
            insn.rn == ArmGpr::kR13 &&
            prev.u == insn.u &&
            prev.i == insn.i &&
            prev.w == 0 &&
            insn.w == 0 &&
            prev.p == 1 &&
            insn.p == 1 &&
            prev.b == 0 &&
            insn.b == 0 &&
            prev.operand2 == insn.operand2) {
            /* "STR X, [SP, #imm]" followed by "LDR Y, [SP, #imm]"
               with the SAME immediate. Replace LDR with "MOV Y, X"
               to skip the round-trip through the MMU. */
            insn.place_fn = &PlaceDataProcessing;
            insn.i        = 0;
            insn.s        = 0;
            insn.opcode   = 13;  /* MOV */
            /* insn.rd is already correct */
            insn.operand2 = prev.rd;
        } else if (prev.entry_point == insn.entry_point &&
                   prev.cond == insn.cond &&
                   prev.place_fn == &PlaceDataProcessing &&
                   prev.opcode == 15 &&  /* MVN */
                   prev.i == 1 &&
                   prev.s == 0 &&
                   prev.rd != ArmGpr::kR15) {
            /* Previous was "MVN X, immediate". Several patterns
               where the MVN's complemented value can be folded
               directly into the next instruction. */
            if (kOptimizeJitCode &&
                insn.place_fn == &PlaceDataProcessing &&
                insn.opcode == 4 &&  /* ADD */
                insn.i == 0 &&
                insn.s == 0 &&
                insn.rd == prev.rd &&
                insn.operand2 == insn.rd) {
                /* MVN X, imm; ADD Y, X, Y → NOP / ADD Y, X, ~imm */
                prev.place_fn  = &PlaceNop;
                insn.i         = 1;
                insn.reserved3 = ~prev.reserved3;
            } else if (insn.place_fn == &PlaceDataProcessing &&
                       insn.opcode == 4 &&  /* ADD */
                       insn.i == 1 &&
                       insn.s == 0 &&
                       insn.rd == ArmGpr::kR15 &&
                       insn.rn == prev.rd) {
                /* MVN X, imm; ADD R15, X, imm2 → B target */
                insn.place_fn = &PlaceBranch;
                insn.l        = 0;
                insn.offset   = static_cast<int32_t>(~prev.reserved3 + insn.reserved3);
                insn.reserved3 = static_cast<uint32_t>(insn.offset);
            } else if (kOptimizeJitCode &&
                       i + 1 < block_ctx_.num_insns &&
                       insn.place_fn == &PlaceDataProcessing &&
                       insn.opcode == 13 &&  /* MOV */
                       insn.i == 0 &&
                       insn.operand2 == ArmGpr::kR15 &&
                       insn.rd == ArmGpr::kR14 &&
                       insn.s == 0 &&
                       block_ctx_.insns[i + 1].entry_point == insn.entry_point &&
                       block_ctx_.insns[i + 1].cond == insn.cond &&
                       block_ctx_.insns[i + 1].place_fn == &PlaceDataProcessing &&
                       block_ctx_.insns[i + 1].opcode == 4 &&  /* ADD */
                       block_ctx_.insns[i + 1].i == 1 &&
                       block_ctx_.insns[i + 1].s == 0 &&
                       block_ctx_.insns[i + 1].rd == ArmGpr::kR15 &&
                       block_ctx_.insns[i + 1].rn == prev.rd) {
                /* MVN X, imm; MOV LR, R15; ADD R15, X, imm2
                   → MVN X, imm; NOP; BL target */
                insn.place_fn = &PlaceNop;
                DecodedInsn& next = block_ctx_.insns[i + 1];
                next.place_fn = &PlaceBranch;
                next.l        = 1;
                next.offset   = static_cast<int32_t>(~prev.reserved3 + next.reserved3);
                next.reserved3 = static_cast<uint32_t>(next.offset);
            }
        } else if (prev.place_fn == &PlaceDataProcessing &&
                   prev.opcode == 13 &&  /* MOV */
                   prev.i == 0 &&
                   prev.rm == ArmGpr::kR15 &&
                   prev.rd == ArmGpr::kR14) {
            /* "MOV LR, PC" — followed by an R15-write is a CALL
               idiom; route to a Place fn that pushes the return
               address onto the per-instance shadow stack. */
            if (insn.place_fn == &PlaceDataProcessing &&
                insn.r15_modified) {
                insn.place_fn = &PlaceDataProcessingCALL;
            } else if (insn.place_fn == &PlaceBx) {
                insn.place_fn = &PlaceBxCALL;
            } else if (insn.place_fn == &PlaceSingleDataTransfer &&
                       insn.rd == ArmGpr::kR15 &&
                       insn.rn != ArmGpr::kR14 &&
                       insn.l) {
                /* LDR PC, [Rn, ...] where Rn isn't LR — CALL. The
                   Rn==LR case is the .NET CF switch-statement
                   dispatch table and must NOT be CALL-ified. */
                insn.place_fn = &PlaceSingleDataTransferCALL;
            }
        } else if (prev.place_fn == &PlaceDataProcessing &&
                   prev.opcode == 4 &&  /* ADD */
                   prev.rd == ArmGpr::kR14 &&
                   prev.rn == ArmGpr::kR15 &&
                   prev.i == 1 &&
                   insn.place_fn == &PlaceDataProcessing &&
                   insn.r15_modified) {
            /* "ADD LR, PC, #Imm" followed by an R15-write — also
               a CALL idiom (e.g. "MOV PC, R12" after "ADD LR, PC, #4"). */
            insn.place_fn = &PlaceDataProcessingCALL;
        } else if (prev.place_fn == &PlaceSingleDataTransfer &&
                   prev.l == 0 &&
                   insn.place_fn == &PlaceSingleDataTransfer &&
                   insn.l == 1 &&
                   insn.rd == ArmGpr::kR15 &&
                   prev.rd == insn.rn) {
            insn.place_fn = &PlaceSingleDataTransferRET;
        }

        else if (kOptimizeJitCode &&
                 i + 3 < block_ctx_.num_insns &&
                 block_ctx_.insns[i + 1].entry_point == insn.entry_point &&
                 block_ctx_.insns[i + 2].entry_point == insn.entry_point &&
                 block_ctx_.insns[i + 3].entry_point == insn.entry_point &&
                 block_ctx_.insns[i + 1].cond == insn.cond &&
                 block_ctx_.insns[i + 2].cond == insn.cond &&
                 insn.place_fn == &PlaceCoprocRegisterTransfer &&
                 insn.l == 0 &&
                 insn.cp_num == 15 &&
                 insn.cp_opc == 0 &&
                 insn.rd == 12 &&
                 insn.crn == 7 &&
                 insn.cp == 2 &&
                 block_ctx_.insns[i + 1].place_fn == &PlaceDataProcessing &&
                 block_ctx_.insns[i + 1].opcode == 4 &&
                 block_ctx_.insns[i + 1].rd == 12 &&
                 block_ctx_.insns[i + 1].operand2 == 3 &&
                 block_ctx_.insns[i + 1].rn == 12 &&
                 block_ctx_.insns[i + 2].place_fn == &PlaceDataProcessing &&
                 block_ctx_.insns[i + 2].opcode == 2 &&
                 block_ctx_.insns[i + 2].i == 1 &&
                 block_ctx_.insns[i + 2].s == 1 &&
                 block_ctx_.insns[i + 2].rd == 1 &&
                 block_ctx_.insns[i + 2].rn == 1 &&
                 block_ctx_.insns[i + 2].reserved3 == 1 &&
                 block_ctx_.insns[i + 3].place_fn == &PlaceBranch &&
                 block_ctx_.insns[i + 3].cond == 5 &&  /* PL */
                 (block_ctx_.insns[i + 3].guest_address -
                  static_cast<uint32_t>(block_ctx_.insns[i + 3].offset)) == 12u) {
            insn.place_fn  = &PlaceDataProcessing;  /* MOVS R1, 0 */
            insn.rd        = 1;
            insn.i         = 1;
            insn.reserved3 = 0;
            insn.opcode    = 13;
            insn.s         = 0;
            /* Tag the last instruction of the recognized inner
               sequence so the outer-loop pattern can confirm the
               first stage ran. */
            dcache_optimization_slot = i + 3;
        }

        else if (kOptimizeJitCode &&
                 i + 1 < block_ctx_.num_insns &&
                 block_ctx_.insns[i + 1].entry_point == insn.entry_point &&
                 i - 1 == dcache_optimization_slot &&
                 insn.place_fn == &PlaceDataProcessing &&
                 insn.opcode == 2 &&
                 insn.i == 1 &&
                 insn.s == 1 &&
                 insn.rd == 0 &&
                 insn.rm == 0 &&
                 insn.reserved3 == 1 &&
                 block_ctx_.insns[i + 1].place_fn == &PlaceBranch &&
                 block_ctx_.insns[i + 1].cond == 5 &&  /* PL */
                 (block_ctx_.insns[i + 1].guest_address -
                  static_cast<uint32_t>(block_ctx_.insns[i + 1].offset)) == 28u) {
            insn.place_fn = &PlaceNop;
            block_ctx_.insns[i + 1].place_fn = &PlaceNop;
            dcache_optimization_slot = static_cast<uint32_t>(-1);
        }

        else if (kOptimizeJitCode &&
                 i + 3 < block_ctx_.num_insns &&
                 block_ctx_.insns[i + 1].entry_point == insn.entry_point &&
                 block_ctx_.insns[i + 2].entry_point == insn.entry_point &&
                 block_ctx_.insns[i + 3].entry_point == insn.entry_point &&
                 block_ctx_.insns[i + 1].cond == insn.cond &&
                 block_ctx_.insns[i + 2].cond == insn.cond &&
                 insn.place_fn == &PlaceCoprocRegisterTransfer &&
                 insn.l == 0 &&
                 insn.cp_num == 15 &&
                 insn.cp_opc == 0 &&
                 insn.rd == 0 &&
                 insn.crn == 7 &&
                 insn.crm == 5 &&
                 insn.cp == 1 &&
                 block_ctx_.insns[i + 1].place_fn == &PlaceDataProcessing &&
                 block_ctx_.insns[i + 1].opcode == 4 &&
                 block_ctx_.insns[i + 1].rd == 0 &&
                 block_ctx_.insns[i + 1].operand2 == block_ctx_.insns[i + 2].operand2 &&
                 block_ctx_.insns[i + 1].rn == 0 &&
                 block_ctx_.insns[i + 2].place_fn == &PlaceDataProcessing &&
                 block_ctx_.insns[i + 2].opcode == 2 &&
                 block_ctx_.insns[i + 2].rd == 1 &&
                 block_ctx_.insns[i + 2].rn == 1 &&
                 block_ctx_.insns[i + 3].place_fn == &PlaceBranch &&
                 block_ctx_.insns[i + 3].cond == 12 &&  /* GT */
                 (block_ctx_.insns[i + 3].guest_address -
                  block_ctx_.insns[i + 3].reserved3) == 12u) {
            /* Sentinel — PlaceCoprocRegisterTransfer reads operand2
               and emits a one-shot range flush instead of per-line. */
            insn.operand2 = 0xFFFFFFFFu;
            block_ctx_.insns[i + 1].place_fn = &PlaceNop;
            block_ctx_.insns[i + 2].place_fn = &PlaceNop;
            block_ctx_.insns[i + 3].place_fn = &PlaceNop;
        }
    }

    return entrypoint_count;
}
