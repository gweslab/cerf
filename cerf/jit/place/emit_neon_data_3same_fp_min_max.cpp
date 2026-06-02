#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_3same_fp_min_max.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VMAX.F32 / VMIN.F32 (A8.8.335) — A7.4.1 opc=1111, B=0, U=0. */
uint8_t* PlaceNeonData3SameFpMinMax(uint8_t*      cursor,
                                    DecodedInsn*  d,
                                    BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const uint32_t w     = d->immediate;
    const uint32_t op    = d->op1;
    const uint32_t Vn    = (w >> 16) & 0xFu;
    const uint32_t Vd    = (w >> 12) & 0xFu;
    const uint32_t Vm    =  w        & 0xFu;
    const uint32_t Dbit  = (w >> 22) & 1u;
    const uint32_t Nbit  = (w >>  7) & 1u;
    const uint32_t Mbit  = (w >>  5) & 1u;
    const uint32_t Q     = (w >>  6) & 1u;
    const uint32_t sz    = (w >> 20) & 1u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t n_idx = (Nbit << 4) | Vn;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* A8.8.335 line 44474: sz==1 UND. */
    if (sz != 0u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* A8.8.335 line 44473. */
    if (Q != 0u && ((d_idx & 1u) || (n_idx & 1u) || (m_idx & 1u))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t regs = Q ? 2u : 1u;

    EmitPush32(cursor, regs);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, n_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon3SameFpMinMax())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon3SameFpMinMax::Handle3SameFpMinMaxHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
