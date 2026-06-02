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

int ArmJit::LocateEntrypoints() {
    /* Instruction size for the cond=14 (AL) end-of-block synthetic
       insn at the end of OptimizeARMFlags / JitGenerateCode; matches
       Cpu.CPSR.Bits.ThumbMode. */
    const uint32_t instruction_size = CpuState()->cpsr.bits.thumb_mode ? 2u : 4u;

    /* Range of the decoded stream — used by branch-into-stream
       checks below. */
    const uint32_t guest_start = block_ctx_.insns[0].actual_guest_address;
    const uint32_t guest_end =
        block_ctx_.insns[block_ctx_.num_insns - 1].actual_guest_address + 1u;

    /* The first instruction always begins an entrypoint. Mark it
       with a non-null tagged value (we use (JitBlock*)1 as the
       boolean marker; the second pass below replaces these markers
       with unique entrypoint-id integers cast to JitBlock*). */
    block_ctx_.insns[0].entry_point =
        reinterpret_cast<JitBlock*>(static_cast<uintptr_t>(1));

    for (uint32_t i = 0; i < block_ctx_.num_insns; ++i) {
        DecodedInsn& insn = block_ctx_.insns[i];

        if (kOptimizeJitCode == false ||
            ((i + 1) < block_ctx_.num_insns && insn.r15_modified)) {
            block_ctx_.insns[i + 1].entry_point =
                reinterpret_cast<JitBlock*>(static_cast<uintptr_t>(1));
        }

        if (insn.place_fn == &PlaceBranch) {
            const uint32_t actual_dest =
                ApplyFcseFold(*mmu_->State(),
                              static_cast<uint32_t>(insn.offset));
            insn.reserved3 = static_cast<uint32_t>(insn.offset);

            if (actual_dest >= guest_start && actual_dest < guest_end) {
                const uint32_t off =
                    (actual_dest - block_ctx_.insns[0].actual_guest_address) /
                    instruction_size;

                block_ctx_.insns[off].entry_point =
                    reinterpret_cast<JitBlock*>(static_cast<uintptr_t>(1));

                if (!processor_config_->GenerateSyscalls() &&
                    off == i - 2 &&
                    block_ctx_.insns[i - 2].place_fn == &PlaceSingleDataTransfer &&
                    block_ctx_.insns[i - 2].w == 0 &&
                    block_ctx_.insns[i - 2].p == 1 &&
                    block_ctx_.insns[i - 2].l == 1 &&
                    block_ctx_.insns[i - 2].b == 0 &&
                    block_ctx_.insns[i - 2].i == 0 &&
                    block_ctx_.insns[i - 2].rd != ArmGpr::kR15 &&
                    block_ctx_.insns[i - 2].rd != block_ctx_.insns[i - 2].rn &&
                    block_ctx_.insns[i - 1].place_fn == &PlaceDataProcessing &&
                    block_ctx_.insns[i - 1].opcode == 10 &&
                    block_ctx_.insns[i - 1].rn == block_ctx_.insns[i - 2].rd &&
                    insn.cond != 14) {
                    insn.place_fn = &PlaceIdleLoop;
                }
            }
        } else if (insn.place_fn == &PlaceDataProcessing &&
                   insn.opcode == 4 &&  /* ADD */
                   insn.rd == ArmGpr::kR14 &&
                   insn.rn == ArmGpr::kR15 &&
                   insn.i == 1) {
            /* "ADD LR, PC, #Imm" — destination is PC + decoded
               immediate. If destination lies inside the stream,
               mark it as an entrypoint so the eventual call into
               it doesn't have to round-trip through R15ModifiedHelper. */
            const uint32_t imm =
                _rotr(static_cast<uint8_t>(insn.operand2),
                      static_cast<int>((insn.operand2 >> 8) << 1));
            const uint32_t actual_dest =
                imm + insn.actual_guest_address +
                (CpuState()->cpsr.bits.thumb_mode ? 4u : 8u);

            if (actual_dest >= guest_start && actual_dest < guest_end) {
                const uint32_t off =
                    (actual_dest - block_ctx_.insns[0].actual_guest_address) /
                    instruction_size;
                block_ctx_.insns[off].entry_point =
                    reinterpret_cast<JitBlock*>(static_cast<uintptr_t>(1));
            }
        }

        /* Compute the FlagsNeeded mask — which CPSR flag bits this
           instruction's condition predicate consumes. */
        insn.flags_needed = static_cast<uint8_t>(kFlagListByCondPair[insn.cond / 2]);

        if (insn.place_fn == &PlaceDataProcessing) {
            if ((insn.opcode == 5 || insn.opcode == 6 || insn.opcode == 7) ||
                (insn.i == 0 && (insn.operand2 & 0xFF0u) == 0x060u)) {
                /* ADC/SBC/RSC + RRX shifter (encoded as ROR #0)
                   read the Carry flag. */
                insn.flags_needed |= static_cast<uint8_t>(kFlagC);
            }
        }

        /* Compute the FlagsSet mask — which CPSR flag bits this
           instruction produces (only when the S-bit is set). */
        if (insn.s) {
            if (insn.place_fn == &PlaceDataProcessing) {
                const uint32_t op = insn.opcode;
                if (op < 2 || op == 8 || op == 9 || op > 11) {
                    /* Logical ops set N/Z/C (no V); they also need
                       C if the shifter_carry_out is sourced from CF. */
                    insn.flags_set    = static_cast<uint8_t>(kFlagN | kFlagZ | kFlagC);
                    insn.flags_needed = static_cast<uint8_t>(kFlagC);
                } else {
                    /* Arithmetic ops set N/Z/C/V. */
                    insn.flags_set = static_cast<uint8_t>(kFlagsAll);
                }

                if (insn.r15_modified) {
                    if (insn.opcode < 8 || insn.opcode > 11) {
                        /* SUBS PC, LR, #X / similar — copies SPSR
                           to CPSR which sets all flags. TST/TEQ/CMP/CMN
                           (8/9/10/11) don't write Rd so this clause
                           skips them. */
                        insn.flags_set = static_cast<uint8_t>(kFlagsAll);
                    }
                }
            } else if (insn.place_fn == &PlaceBlockDataTransfer) {
                if (insn.l && insn.r15_modified) {
                    /* LDM with PC in register-list and S-bit set:
                       loads SPSR → CPSR; all flags affected. */
                    insn.flags_set = static_cast<uint8_t>(kFlagsAll);
                }
            } else if (insn.place_fn == &PlaceArithmeticExtension) {
                /* QADD / QSUB / etc set Q (not modelled) and N/Z. */
                insn.flags_set = static_cast<uint8_t>(kFlagN | kFlagZ);
            } else if (insn.place_fn == &PlaceMSRImmediate) {
                /* MSR CPSR_f, #Imm — write to CPSR flags field
                   when bit 3 of the field-mask Rn is set and op1
                   bit 1 is clear (CPSR vs SPSR). */
                if (!(insn.op1 & 2u) && (insn.rn & 8u)) {
                    insn.flags_set = static_cast<uint8_t>(kFlagsAll);
                }
            } else if (insn.place_fn == &PlaceMRSorMSR) {
                if (insn.op1 == 1) {
                    /* MSR CPSR, Rm — full CPSR write. */
                    insn.flags_set = static_cast<uint8_t>(kFlagsAll);
                } else if (insn.op1 == 0) {
                    /* MRS Rd, CPSR — reads all flags. */
                    insn.flags_needed |= static_cast<uint8_t>(kFlagsAll);
                }
            } else if (insn.place_fn == &PlaceLoadStoreExtension) {
                /* LDRSH / STRD / similar — S-bit is a sign-extend
                   selector, not a flag-set request. No flags. */
            } else {
                /* S-bit set on a place_fn that doesn't model the
                   S effect — programmer / decoder error. */
                LOG(Caution, "ArmJit::LocateEntrypoints: S-bit set on insn at "
                    "0x%08X with unhandled place_fn\n", insn.guest_address);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
        }
    }

    int entrypoint_counter = 1;
    uint32_t i = 0;
    while (i < block_ctx_.num_insns) {
        block_ctx_.insns[i].entry_point =
            reinterpret_cast<JitBlock*>(static_cast<uintptr_t>(entrypoint_counter));

        uint32_t j = i + 1;
        for (; j < block_ctx_.num_insns; ++j) {
            if (block_ctx_.insns[j].entry_point) {
                /* Marker present — start of next entrypoint. */
                break;
            }
            block_ctx_.insns[j].entry_point =
                reinterpret_cast<JitBlock*>(static_cast<uintptr_t>(entrypoint_counter));
        }
        i = j;
        ++entrypoint_counter;
    }

    /* entrypoint_counter started at 1 and incremented after each
       entrypoint, so the count is one less than the final value. */
    return entrypoint_counter - 1;
}
