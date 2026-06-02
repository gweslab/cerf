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
#include "arm_cpu.h"
#include "arm_cpu_exceptions.h"
#include "arm_cpu_ops.h"
#include "arm_jit_runtime.h"
#include "arm_mmu.h"
#include "translate_helpers.h"
#include "arm_mmu_state.h"
#include "place_fns.h"
#include "x86_emit.h"

#if CERF_DEV_MODE
#include "../tracing/trace_manager.h"
#endif

#if CERF_DEV_MODE
void __cdecl ArmJit::TraceDispatchPcHelper(ArmJit*      jit,
                                           uint32_t     pc,
                                           ArmCpuState* state) {
    const uint32_t cpsr = ArmCpuGetCpsrWithFlags(state);
    jit->emu_.Get<TraceManager>().DispatchPc(pc, state->gprs, cpsr);
}
#endif

void ArmJit::JitApplyFixups() {
    using namespace x86;

    const uint32_t instruction_size = CpuState()->cpsr.bits.thumb_mode ? 2u : 4u;

    for (uint32_t i = 0; i < block_ctx_.num_insns; ++i) {
        DecodedInsn& insn = block_ctx_.insns[i];

        if (!insn.jmp_fixup_location) {
            continue;
        }

        const uint32_t off = (insn.reserved3 -
                              block_ctx_.insns[0].guest_address) /
                             instruction_size;

        if (off >= block_ctx_.num_insns) {
            LOG(Caution, "ArmJit::JitApplyFixups: target offset %u out of "
                "stream (num_insns=%u) for fixup at insn[%u] guest_addr=0x%08X "
                "target=0x%08X\n",
                off, block_ctx_.num_insns, i, insn.guest_address,
                insn.reserved3);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        if (block_ctx_.insns[off].guest_address != insn.reserved3) {
            LOG(Caution, "ArmJit::JitApplyFixups: target offset %u guest_addr "
                "0x%08X != recorded target 0x%08X for fixup at insn[%u]\n",
                off, block_ctx_.insns[off].guest_address, insn.reserved3, i);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        uint8_t* cursor = insn.jmp_fixup_location;
        EmitJmp32(cursor, block_ctx_.insns[off].entry_point->native_start);
    }
}

size_t ArmJit::JitGenerateCode(uint8_t* code_location, int /* entrypoint_count */) {
    if (block_ctx_.num_insns == 0) {
        LOG(Caution, "ArmJit::JitGenerateCode called with num_insns == 0\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    uint8_t* original_code_location = code_location;
    JitBlock* ep = nullptr;
    uint32_t previous_cond = 16;  /* Illegal value — guarantees first
                                     instruction triggers a cond-change. */

    /* Per-block emit context resets — each compile starts with no
       pending Jcc skip-fixups and no cached PC-relative load. */
    block_ctx_.big_skip_count   = 0;
    block_ctx_.pc_cache_valid   = false;

#if CERF_DEV_MODE
    /* Resolve TraceManager once per compile so the per-instruction
       HasPcTrace check below is a single map lookup, not a
       per-instruction service-locator call. */
    TraceManager& tm = emu_.Get<TraceManager>();
#endif

    ArmProcessorConfig& pcfg = emu_.Get<ArmProcessorConfig>();
    constexpr int32_t kCycleCounterOff =
        static_cast<int32_t>(offsetof(ArmCpuState, guest_cycle_counter));

    for (uint32_t i = 0; i < block_ctx_.num_insns; ++i) {
        DecodedInsn& insn = block_ctx_.insns[i];

        if (insn.entry_point != ep) {
            PlaceEndConditionCheck(code_location, &block_ctx_);
            previous_cond = 16;

            if (ep) {
                DecodedInsn end_ep{};
                end_ep.r15_modified  = 1;
                end_ep.cond          = 14;
                end_ep.place_fn      = &PlaceEntrypointEnd;
                end_ep.guest_address = insn.guest_address;
                code_location = PlaceEntrypointMiddle(code_location,
                                                      &end_ep,
                                                      &block_ctx_);
                ep->native_end = code_location;
            }

            ep = insn.entry_point;
            ep->native_start = code_location;
            block_ctx_.pc_cache_valid = false;
        }

        if (insn.cond != previous_cond) {
            /* Cond changed — close any pending skip-fixups for the
               previous cond-run, then start a new run if this
               cond is < 14 (unconditional cond=14 needs no guard). */
            PlaceEndConditionCheck(code_location, &block_ctx_);
            previous_cond = insn.cond;
            if (previous_cond < 14u) {
                block_ctx_.big_skips1[block_ctx_.big_skip_count] = nullptr;
                block_ctx_.big_skips2[block_ctx_.big_skip_count] = nullptr;
                code_location = PlaceConditionCheck(code_location,
                                                    &insn,
                                                    &block_ctx_);
                ++block_ctx_.big_skip_count;
            }
        } else {
            /* Same cond as previous insn AND the previous insn
               touched the flags — must re-emit the cond guard
               since the flag state under test has changed. */
            if (previous_cond < 14u && i > 0u &&
                block_ctx_.insns[i - 1].flags_set) {
                block_ctx_.big_skips1[block_ctx_.big_skip_count] = nullptr;
                block_ctx_.big_skips2[block_ctx_.big_skip_count] = nullptr;
                code_location = PlaceConditionCheck(code_location,
                                                    &insn,
                                                    &block_ctx_);
                ++block_ctx_.big_skip_count;
            }
        }

#if CERF_DEV_MODE
        if (tm.HasPcTrace(insn.guest_address)) {
            using namespace x86;
            EmitPushReg(code_location, kEsi);
            EmitPush32 (code_location, insn.guest_address);
            EmitPush32 (code_location,
                        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(this)));
            EmitCall   (code_location,
                        reinterpret_cast<void*>(&ArmJit::TraceDispatchPcHelper));
            EmitAddRegImm32(code_location, kEsp, 12);
        }
#endif

        {
            using namespace x86;
            const uint16_t cost = pcfg.CycleCostFor(insn);
            EmitAddBaseDisp32Imm8(code_location, kEsi, kCycleCounterOff,
                                  static_cast<uint8_t>(cost));
        }

        /* Per-instruction emit. */
        code_location = (insn.place_fn)(code_location, &insn, &block_ctx_);
    }

    PlaceEndConditionCheck(code_location, &block_ctx_);

    DecodedInsn end_ep{};
    end_ep.r15_modified  = 1;
    end_ep.cond          = 14;
    end_ep.place_fn      = &PlaceEntrypointEnd;
    end_ep.guest_address =
        block_ctx_.insns[block_ctx_.num_insns - 1].guest_address +
        (CpuState()->cpsr.bits.thumb_mode ? 2u : 4u);

    code_location = PlaceEntrypointEnd(code_location,
                                       &end_ep,
                                       &block_ctx_);
    if (ep) {
        ep->native_end = code_location;
    }

    return static_cast<size_t>(code_location - original_code_location);
}

void ArmJit::JitCreateEntrypoints(JitBlock* containing_block,
                                  uint8_t*  prefix_slab) {
    IsaBlockSpace& space =
        CpuState()->cpsr.bits.thumb_mode ? blocks_thumb_ : blocks_arm_;
    const uint8_t asid = static_cast<uint8_t>(mmu_->State()->contextidr & 0xFFu);

    /* Outer entrypoints route by nG (the decoded region is one
       contiguous range → uniform): global (kernel/shared) → shared
       tree; user (nG=1) → per-ASID. Subs chain off containing_block,
       so PlaceSubAt's owning tree is irrelevant. */
    const bool outer_global =
        containing_block
            ? false
            : mmu_->ExecPageGlobal(block_ctx_.insns[0].actual_guest_address);
    JitBlockIndex& outer_idx =
        outer_global ? space.global : space.per_asid[asid];

    const size_t per_entry_size = containing_block
        ? JitBlockIndex::SubEntrySize()
        : JitBlockIndex::OuterEntrySize();

    JitBlock* prev_marker = block_ctx_.insns[0].entry_point;

    uint32_t i           = 0;
    size_t   slot_offset = 0;
    while (i < block_ctx_.num_insns) {
        /* Walk forward until we find the first insn whose marker
           differs from prev_marker. j ends pointing at either that
           insn (boundary) or num_insns (end of stream). */
        uint32_t j = i + 1;
        for (; j < block_ctx_.num_insns; ++j) {
            if (block_ctx_.insns[j].entry_point != prev_marker) {
                /* Boundary — record the new marker for the next
                   group's processing. */
                prev_marker = block_ctx_.insns[j].entry_point;
                break;
            }
        }

        JitBlock new_block{};
        new_block.guest_start  = block_ctx_.insns[i].actual_guest_address;
        new_block.phys_start   = block_ctx_.block_phys_page_base |
            (block_ctx_.insns[i].actual_guest_address & 0x00000FFFu);
        new_block.flags_needed = static_cast<uint32_t>(kFlagsAll);
        new_block.native_start = nullptr;
        new_block.native_end   = nullptr;
        new_block.sub_block    = nullptr;

        if (j < block_ctx_.num_insns) {
            /* Mid-stream entrypoint — guest_end is one byte before
               the next entrypoint's guest_start. */
            new_block.guest_end =
                block_ctx_.insns[j].actual_guest_address - 1u;
        } else {
            /* Last entrypoint — guest_end covers the last
               instruction's address + (instruction_size - 1). */
            new_block.guest_end =
                block_ctx_.insns[j - 1].actual_guest_address +
                (CpuState()->cpsr.bits.thumb_mode ? 1u : 3u);
        }

        void* slot = prefix_slab + slot_offset;
        slot_offset += per_entry_size;

        JitBlock* stored;
        if (containing_block) {
            stored = outer_idx.PlaceSubAt(slot, containing_block, new_block);
        } else {
            stored = outer_idx.PlaceOuterAt(slot, new_block);
            space.IndexInsert(stored, &outer_idx);
        }

        for (uint32_t k = i; k < j; ++k) {
            block_ctx_.insns[k].entry_point = stored;
        }

        i = j;
    }

    if (!containing_block && !outer_global) {
        space.MarkPopulated(asid);
    }
}
