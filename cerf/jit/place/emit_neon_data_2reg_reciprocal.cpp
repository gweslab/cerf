#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_2reg_reciprocal.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VRECPE / VRSQRTE (A8.8.384 / A8.8.391) — A7.4.5 A=11, bits[10:9]=10,
   bit[8]=F integer/.F32, bit[7] selects op (0=VRECPE, 1=VRSQRTE). */
uint8_t* PlaceNeonData2RegReciprocal(uint8_t*      cursor,
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
    const uint32_t F     = (w >>  8) & 1u;
    const uint32_t size  = (w >> 18) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* A8.8.384 line 49089 / A8.8.391 line 49750: size != 10 UND. */
    if (size != 2u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* A8.8.384 line 49088 / A8.8.391 line 49749. */
    if (Q != 0u && ((d_idx & 1u) || (m_idx & 1u))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t regs = Q ? 2u : 1u;

    EmitPush32(cursor, regs);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, F);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon2RegReciprocal())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon2RegReciprocal::HandleReciprocalHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
