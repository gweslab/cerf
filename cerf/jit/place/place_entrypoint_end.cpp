#include <cstddef>

#include "../arm_jit.h"
#include "../arm_mmu.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* PlaceEntrypointEnd(uint8_t*      cursor,
                            DecodedInsn*  d,
                            BlockContext* ctx) {
    using namespace x86;

    /* Deliver pending interrupts before exiting the block. */
    cursor = PlaceInterruptPoll(cursor, d, ctx);

    const int32_t r15_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15 * 4);

    /* Fall-through across a 4 KB page boundary: the next VA remaps to a
       different phys on a context switch. Chain via the jump cache (indirect
       JMP on hit, RETN to dispatcher on miss); a baked JMP would go stale. */
    const uint32_t src_page = ctx->insns[0].guest_address & 0xFFFFF000u;
    if ((d->guest_address & 0xFFFFF000u) != src_page) {
        EmitMovRegImm32(cursor, kEcx, d->guest_address);
        EmitCall(cursor, ctx->cross_page_branch_helper_target);
        return cursor;
    }

    /* update_location is where EntrypointEndHelper patches the JMP-rel32. */
    uint8_t* update_location = cursor;

    /* Same page → phys-stable. If the next block is already translated, emit
       a direct JMP to its native_start (resolved by phys). */
    const uint32_t dst_phys =
        ctx->block_phys_page_base | (d->guest_address & 0x00000FFFu);
    const uint32_t dst_fva =
        ApplyFcseFold(*ctx->jit->Mmu()->State(), d->guest_address);
    JitBlock* ep = ctx->jit->LookupBlockByVaPhys(dst_fva, dst_phys);
    if (ep) {
        EmitJmp32(cursor, ep->native_start);
        return cursor;
    }

    /* Not yet translated: resolve at runtime (jump cache → native in EAX);
       EntrypointEndHelper self-patches update_location into a JMP rel32. */
    EmitPush32(cursor, d->guest_address);              /* arg2: guest_pc */
    EmitPush32(cursor,
               static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ctx->jit)));
                                                        /* arg1: jit */
    EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::FindBlockNativeStartHelper));
    EmitAddRegImm32(cursor, kEsp, 8);

    EmitTestRegReg(cursor, kEax, kEax);
    uint8_t* not_in_cache = EmitJzLabel(cursor);

    EmitMovRegImm32(cursor, kEdi,
                    static_cast<uint32_t>(reinterpret_cast<uintptr_t>(update_location)));
    EmitJmp32(cursor, reinterpret_cast<void*>(&ArmJit::EntrypointEndHelper));

    FixupLabel(not_in_cache, cursor);
    EmitMovBaseDisp32Imm32(cursor, kStateReg, r15_disp, d->guest_address);
    EmitRetn(cursor, 0);
    return cursor;
}
