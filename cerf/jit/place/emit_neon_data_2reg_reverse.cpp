#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_2reg_reverse.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VREV16/VREV32/VREV64 (A8.8.386). bit[6]=Q selects D vs Q form. */
uint8_t* PlaceNeonData2RegReverse(uint8_t*      cursor,
                                  DecodedInsn*  d,
                                  BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const uint32_t w     = d->immediate;
    const uint32_t op    = d->op1;
    const uint32_t Vd    = (w >> 12) & 0xFu;
    const uint32_t Vm    =  w        & 0xFu;
    const uint32_t Dbit  = (w >> 22) & 1u;
    const uint32_t Mbit  = (w >>  5) & 1u;
    const uint32_t Q     = (w >>  6) & 1u;
    const uint32_t size  = (w >> 18) & 3u;
    const uint32_t opbit = (w >>  7) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* op + size >= 3 UND per A8.8.386 line 49267. */
    if (opbit + size >= 3u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* Q && (Vd<0> || Vm<0>) UND per A8.8.386 line 49268. */
    if (Q != 0u && ((d_idx & 1u) || (m_idx & 1u))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t esize     = 8u << size;
    const uint32_t groupsize = 1u << (3u - opbit - size);
    const uint32_t regs      = Q ? 2u : 1u;

    EmitPush32(cursor, regs);
    EmitPush32(cursor, groupsize);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon2RegReverse())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon2RegReverse::HandleRevHelper));
    EmitAddRegImm32(cursor, kEsp, 28);
    return cursor;
}
