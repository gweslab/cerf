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
#include "arm_decoder.h"
#include "arm_jit_runtime.h"
#include "arm_mmu.h"
#include "arm_mmu_state.h"
#include "place_fns.h"
#include "x86_emit.h"

void ArmJit::JitDecode(JitBlock* containing_block, uint32_t guest_pc) {
    int instruction_size;
    if (cpu_->State()->cpsr.bits.thumb_mode) {
        instruction_size = 2;
        guest_pc &= 0xFFFFFFFEu;
    } else {
        instruction_size = 4;
        guest_pc &= 0xFFFFFFFCu;
    }

    /* end_address is FOLDED-VA (the loop compares folded actual_guest_pc),
       bounded to one 4 KB page so phys = page_base | (folded & 0xFFF) stays
       unambiguous. Next-block bound is phys-keyed, mapped back via page base. */
    const uint32_t folded_pc = ApplyFcseFold(*mmu_->State(), guest_pc);
    const uint32_t page_end  = (folded_pc & 0xFFFFF000u) + 0x1000u;

    uint32_t end_address;
    if (containing_block) {
        end_address = containing_block->guest_end;
    } else {
        const uint32_t next_va = NextBlockStart(folded_pc);
        if (next_va != 0xFFFFFFFFu &&
            (next_va & 0xFFFFF000u) == (folded_pc & 0xFFFFF000u)) {
            end_address = next_va;
        } else {
            end_address = page_end;
        }
    }
    if (end_address > page_end) end_address = page_end;

    /* Reset the decoded array. block_ctx_ is reused between
       JitCompile invocations; each call starts with a clean slate. */
    std::memset(block_ctx_.insns, 0, sizeof(block_ctx_.insns));

    /* Apply FCSE fold once; thereafter both `guest_pc` (the raw
       guest-visible address) and `actual_guest_pc` (the post-fold
       PA-side address used for memory access) advance in lockstep
       by instruction_size. */
    uint32_t actual_guest_pc = ApplyFcseFold(*mmu_->State(), guest_pc);

    uint32_t i;
    for (i = 0;
         i < kMaxInsnPerBlock && actual_guest_pc < end_address;
         ++i, guest_pc += instruction_size, actual_guest_pc += instruction_size) {
        DecodedInsn& insn = block_ctx_.insns[i];

        insn.guest_address        = guest_pc;
        insn.actual_guest_address = actual_guest_pc;
        insn.jmp_fixup_location   = nullptr;

        /* Translate guest VA to host pointer for instruction fetch.
           MMU-on path goes through the page-table walker + ITLB;
           MMU-off path is identity (VA == PA) and consults
           EmulatedMemory directly. */
        uint8_t* host_addr;
        if (mmu_->State()->control_register.bits.m) {
            host_addr = mmu_->TranslateExecute(cpu_->State(), actual_guest_pc);
        } else {
            host_addr = memory_->TryTranslate(actual_guest_pc);
        }

        if (!host_addr) {
            if (mmu_->io_pending_address() != 0) {
                LOG(Caution,
                    "ArmJit::JitDecode: attempt to execute from I/O space "
                    "at guest PA 0x%08X\n", actual_guest_pc);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }

            if (guest_pc > 0xF0000000u) {
                /* Synthetic entry: at runtime, restore the MMU
                   fault state captured here and dispatch to the
                   prefetch-abort vector. */
                insn.place_fn      = &PlaceRaiseAbortPrefetchException;
                insn.guest_address = guest_pc;
                insn.cond          = 14;  /* AL — unconditional */
                insn.immediate     = mmu_->State()->fault_address;
                insn.reserved3     = mmu_->State()->fault_status.word;
                ++i;
                break;
            }

            /* Stop decoding; JitCompile evaluates num_insns and,
               if zero, raises CpuRaiseAbortPrefetchException
               directly. */
            break;
        }

        if (cpu_->State()->cpsr.bits.thumb_mode) {
            uint16_t opcode_word;
            std::memcpy(&opcode_word, host_addr, sizeof(opcode_word));
            if (!decoder_->DecodeThumb(&insn, opcode_word)) {
                ++i;
                break;
            }
        } else {
            uint32_t opcode_word;
            std::memcpy(&opcode_word, host_addr, sizeof(opcode_word));
            if (!decoder_->DecodeArm(&insn, opcode_word)) {
                ++i;
                break;
            }

            if (opcode_word == 0xEAFFFFFEu &&
                actual_guest_pc == 0x92001010u) {
                insn.place_fn = &PlacePowerDown;
            }
        }

        /* Stop at an unconditional control-leave (return / uncond jump):
           bytes after are unreachable by fall-through (inline literal
           pools); decoding them marks their words as code, false-tripping
           the SMC flush. BL/BLX are calls (return falls through) — exclude. */
        if (insn.r15_modified && insn.cond == 14u &&
            !(insn.place_fn == &PlaceBranch && insn.l) &&
            insn.place_fn != &PlaceBlxReg) {
            ++i;
            break;
        }
    }

    block_ctx_.num_insns = i;
}

void* ArmJit::JitCompile(uint32_t guest_pc) {
    uint32_t cached_fault_status  = mmu_->State()->fault_status.word;
    uint32_t cached_fault_address = mmu_->State()->fault_address;

    JitBlock* containing_block = nullptr;

    do {
        /* Resolve insn[0]'s PA from the fetch itself (this also warms the
           I-TLB for the decode that follows) — never a separate page-table
           walk, which would diverge from the fetch mid-TTBR0-setup. MMU
           off ⇒ VA == PA. */
        const bool     mmu_on  = mmu_->State()->control_register.bits.m;
        const uint32_t aligned = cpu_->State()->cpsr.bits.thumb_mode
            ? (guest_pc & 0xFFFFFFFEu) : (guest_pc & 0xFFFFFFFCu);
        uint8_t* h0 = mmu_on
            ? mmu_->TranslateExecute(cpu_->State(), aligned)
            : memory_->TryTranslate(aligned);

        if (h0) {
            const uint32_t phys0 = mmu_on ? mmu_->LastExecPa() : aligned;
            block_ctx_.block_phys_page_base = phys0 & 0xFFFFF000u;
            const uint32_t fva = ApplyFcseFold(*mmu_->State(), guest_pc);
            IsaBlockSpace& space =
                cpu_->State()->cpsr.bits.thumb_mode ? blocks_thumb_ : blocks_arm_;

            /* A phys mismatch on a folded-VA dedup hit is an FCSE-PID-reuse
               stale block at the same VA; evict it or the recompile inserts
               a duplicate VA key the next dedup keeps missing → unbounded
               tree growth. */
            if (JitBlock* ex = LookupBlockExact(fva)) {
                if (ex->phys_start == phys0) {
                    mmu_->State()->fault_status.word = cached_fault_status;
                    mmu_->State()->fault_address     = cached_fault_address;
                    space.JumpCacheInsert(fva, ex->native_start);
                    return ex->native_start;
                }
                space.RemoveExact(fva);
            }
            containing_block = LookupBlockContaining(fva);
            if (containing_block &&
                containing_block->phys_start !=
                    (block_ctx_.block_phys_page_base |
                     (containing_block->guest_start & 0x00000FFFu))) {
                /* Stale containing outer (same VA region, different phys) —
                   evict so we don't sub-entry into dead native. */
                space.RemoveExact(containing_block->guest_start);
                containing_block = nullptr;
            }
        } else {
            /* Fetch faulted. JitDecode may still emit a synthetic prefetch-abort
               block (guest_pc > 0xF0000000); key it off the VA page so its
               phys_start stays a high, non-colliding address in the index. */
            block_ctx_.block_phys_page_base = aligned & 0xFFFFF000u;
            containing_block = nullptr;
        }

        /* Disassemble guest instructions starting at `guest_pc`
           into block_ctx_.insns[]. Sets block_ctx_.num_insns. */
        JitDecode(containing_block, guest_pc);

        if (block_ctx_.num_insns == 0) {
            (void)cpu_->RaiseAbortPrefetchException(guest_pc);

            void* abort_native = NativeAddr(ExceptionVector::kAbortPrefetch);
            if (abort_native) {
                return abort_native;
            }
            void* lookup = FindBlockNativeStart(cpu_->State()->gprs[15]);
            if (lookup) {
                SetNativeAddr(ExceptionVector::kAbortPrefetch, lookup);
                return lookup;
            }

            /* Vector block not translated. Loop with the new R15
               (now pointing at the vector) and re-cache MMU fault
               state for the kernel ISR to observe. */
            guest_pc             = cpu_->State()->gprs[15];
            cached_fault_status  = mmu_->State()->fault_status.word;
            cached_fault_address = mmu_->State()->fault_address;
        }
    } while (block_ctx_.num_insns == 0);

    /* Locate entrypoints + run flag-elimination passes. Returns the
       count of entrypoints discovered inside the decoded block. */
    int entrypoint_count = JitOptimizeIR();

    const size_t per_entry_size = containing_block
        ? JitBlockIndex::SubEntrySize()
        : JitBlockIndex::OuterEntrySize();
    const size_t ep_size        = static_cast<size_t>(entrypoint_count) * per_entry_size;

    constexpr size_t kCodeSize = 32u * 1024u;
    uint8_t* slab          = arena_.Allocate(ep_size + kCodeSize);
    if (!slab) {
        FlushTranslationCache(0u, 0xFFFFFFFFu);
        containing_block = nullptr;

        const size_t ep_size_retry =
            static_cast<size_t>(entrypoint_count) * JitBlockIndex::OuterEntrySize();
        slab = arena_.Allocate(ep_size_retry + kCodeSize);
        if (!slab) {
            LOG(Caution,
                "ArmJit::JitCompile: arena allocation of %zu bytes failed twice "
                "after flush\n", ep_size_retry + kCodeSize);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }

    /* After the (possible) flush + reallocation, recompute ep_size
       for the post-flush case (containing_block may now be null and
       sizes may have changed). */
    const size_t final_ep_size = (containing_block ? JitBlockIndex::SubEntrySize()
                                                   : JitBlockIndex::OuterEntrySize())
                                 * static_cast<size_t>(entrypoint_count);
    uint8_t* code_location = slab + final_ep_size;

    /* Register the entrypoints into the prefix slab. JitCreateEntrypoints
       lays out per_entry_size bytes per entrypoint at slab[0], slab[1],
       ... and stashes a per-insn entry_point pointer. */
    JitCreateEntrypoints(containing_block, slab);

    /* Drop dead CPSR flag packs across the decoded instructions. */
    OptimizeARMFlags();

    /* Emit host x86 into the suffix. Returns the bytes actually used. */
    size_t native_size = JitGenerateCode(code_location, entrypoint_count);

    /* Patch within-batch forward jumps now that every entrypoint's
       native_start is finalized. */
    JitApplyFixups();

    /* Restore MMU fault state — the decoder's instruction-fetch
       translations may have overwritten it. */
    mmu_->State()->fault_status.word = cached_fault_status;
    mmu_->State()->fault_address     = cached_fault_address;

    /* Return the unused tail of the arena allocation — past records
       AND past emitted code. */
    arena_.FreeUnusedTail(code_location + native_size);

    /* Make the freshly emitted bytes visible to the host CPU's
       instruction-fetch pipeline. */
    FlushInstructionCache(GetCurrentProcess(), code_location,
                          static_cast<SIZE_T>(native_size));

    void* native = reinterpret_cast<JitBlock*>(slab)->native_start;
    (cpu_->State()->cpsr.bits.thumb_mode ? blocks_thumb_ : blocks_arm_)
        .JumpCacheInsert(ApplyFcseFold(*mmu_->State(), guest_pc), native);
    return native;
}
