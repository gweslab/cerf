#include <cstddef>

#include "../arm_jit.h"
#include "../arm_jit_runtime.h"
#include "../arm_mmu.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* PlaceBranch(uint8_t*      cursor,
                     DecodedInsn*  d,
                     BlockContext* ctx) {
    using namespace x86;

    /* BL: write LR = guest_pc + 4 (instruction-after-BL) and push
       the return address onto the per-instance shadow stack so a
       future BX LR / MOV PC, LR can JMP straight to the cached
       host code without round-tripping through R15ModifiedHelper. */
    if (d->l) {
        EmitMovBaseDisp32Imm32(cursor, kStateReg,
                               static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 14 * 4),
                               d->guest_address + 4u);
        cursor = PlacePushShadowStack(cursor, d, ctx);
    }

    if (d->reserved3 <= d->guest_address) {
        cursor = PlaceInterruptPoll(cursor, d, ctx);
    }

    /* Destination inside the current compile batch AND it's a
       known entrypoint? Reserve 5 bytes for a back-patched JMP
       rel32; JitApplyFixups fills it in once every entrypoint's
       native_start is finalized. */
    if (d->reserved3 >= ctx->insns[0].guest_address &&
        d->reserved3 <= ctx->insns[ctx->num_insns - 1].guest_address) {
        const uint32_t instruction_size =
            ctx->jit->CpuState()->cpsr.bits.thumb_mode ? 2u : 4u;
        const uint32_t off =
            (d->reserved3 - ctx->insns[0].guest_address) / instruction_size;

        if (ctx->insns[off].entry_point->guest_start ==
            ApplyFcseFold(*ctx->jit->Mmu()->State(), d->reserved3)) {
            d->jmp_fixup_location = cursor;
            cursor += 5;  /* JMP rel32 placeholder filled by JitApplyFixups */
            return cursor;
        }
    }

    /* Bake a direct JMP only for a same-page target: cross-page, the target VA
       remaps to a different phys on a context switch, so a baked JMP would jump
       into the prior process's stale block. Cross-page re-resolves via the cache. */
    const uint32_t src_page  = ctx->insns[0].guest_address & 0xFFFFF000u;
    const bool     same_page = (d->reserved3 & 0xFFFFF000u) == src_page;

    if (same_page) {
        const uint32_t dst_phys =
            ctx->block_phys_page_base | (d->reserved3 & 0x00000FFFu);
        const uint32_t dst_fva =
            ApplyFcseFold(*ctx->jit->Mmu()->State(), d->reserved3);
        JitBlock* ep = ctx->jit->LookupBlockByVaPhys(dst_fva, dst_phys);
        if (ep) {
            /* Already translated → direct JMP rel32 (phys-stable). */
            EmitJmp32(cursor, ep->native_start);
        } else {
            /* MOV ECX, dest; CALL branch_helper. Resolves at runtime and
               self-patches this 10-byte sequence into a JMP rel32 on hit —
               safe to bake because same-page. */
            EmitMovRegImm32(cursor, kEcx, d->reserved3);
            EmitCall(cursor, ctx->branch_helper_target);
        }
    } else {
        /* Cross-page: chain via the jump cache (indirect JMP on hit, RETN to
           dispatcher on miss); a baked JMP would go stale on a context switch. */
        EmitMovRegImm32(cursor, kEcx, d->reserved3);
        EmitCall(cursor, ctx->cross_page_branch_helper_target);
    }
    return cursor;
}
