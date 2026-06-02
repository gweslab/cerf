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

void ArmJit::OptimizeARMFlags() {
    uint32_t known_flags_needed[kMaxInsnPerBlock] = {};

    const uint32_t guest_start = block_ctx_.insns[0].actual_guest_address;
    const uint32_t guest_end =
        block_ctx_.insns[block_ctx_.num_insns - 1].actual_guest_address + 1u;

    const uint32_t instruction_size = CpuState()->cpsr.bits.thumb_mode ? 2u : 4u;

    bool pass_needed = true;
    uint32_t pass_number = 0;

    while (pass_needed) {
        pass_needed = false;
        ++pass_number;
        if (pass_number > 2) {
            LOG(Caution, "ArmJit::OptimizeARMFlags: pass_number > 2 "
                "(algorithm should converge in two passes)\n");
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        uint32_t flags_needed = static_cast<uint32_t>(kFlagsAll);
        uint32_t i = block_ctx_.num_insns;

        do {
            --i;
            DecodedInsn& insn = block_ctx_.insns[i];

            if (insn.flags_needed || insn.flags_set || insn.r15_modified) {
                uint32_t flags_to_generate =
                    flags_needed & static_cast<uint32_t>(insn.flags_set);

                insn.flags_set = static_cast<uint8_t>(flags_to_generate);

                if (insn.flags_needed) {
                    flags_needed |= static_cast<uint32_t>(insn.flags_needed);
                } else {
                    flags_needed =
                        (flags_needed & ~flags_to_generate) |
                        static_cast<uint32_t>(insn.flags_needed);
                }

                if (insn.r15_modified) {
                    if (i < block_ctx_.num_insns - 1) {
                        block_ctx_.insns[i + 1].entry_point->flags_needed =
                            known_flags_needed[i + 1];
                    }

                    if (insn.place_fn == &PlaceBranch) {
                        const uint32_t actual_dest =
                            ApplyFcseFold(*mmu_->State(), insn.reserved3);

                        if (actual_dest >= guest_start && actual_dest < guest_end) {
                            if (actual_dest > insn.actual_guest_address) {
                                uint32_t new_flags_needed =
                                    static_cast<uint32_t>(kFlagsAll);
                                const uint32_t distance =
                                    (actual_dest - insn.actual_guest_address) /
                                    instruction_size;

                                if (block_ctx_.insns[i + distance].actual_guest_address ==
                                    actual_dest) {
                                    new_flags_needed = known_flags_needed[i + distance];
                                }
                                flags_needed |= new_flags_needed;
                            } else {
                                if (pass_number == 1) {
                                    pass_needed = true;
                                    flags_needed =
                                        static_cast<uint32_t>(kFlagsAll);
                                } else {
                                    uint32_t new_flags_needed =
                                        static_cast<uint32_t>(kFlagsAll);
                                    const uint32_t distance =
                                        (insn.actual_guest_address - actual_dest) /
                                        instruction_size;

                                    if (block_ctx_.insns[i - distance].actual_guest_address ==
                                        actual_dest) {
                                        new_flags_needed =
                                            known_flags_needed[i - distance];
                                    }
                                    flags_needed |= new_flags_needed;
                                }
                            }
                        } else {
                            JitBlock* ep = LookupBlockExact(actual_dest);
                            if (ep) {
                                flags_needed |= ep->flags_needed;
                            } else {
                                flags_needed = static_cast<uint32_t>(kFlagsAll);
                            }
                        }
                    } else {
                        /* Branch to a runtime-computed destination
                           (BX, MOV PC, ...). Conservative. */
                        flags_needed = static_cast<uint32_t>(kFlagsAll);
                    }
                }
            }

            known_flags_needed[i] = flags_needed;
        } while (i);
    }

    /* Final commit: write the entry-of-block flags-needed onto the
       first instruction's entrypoint. JitGenerateCode reads this
       to decide whether to emit a leading flag-pack on entry. */
    block_ctx_.insns[0].entry_point->flags_needed = known_flags_needed[0];
}
