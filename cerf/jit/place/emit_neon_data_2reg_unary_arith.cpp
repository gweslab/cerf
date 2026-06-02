#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_2reg_unary_arith.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VABS / VNEG (A8.8.280 / A8.8.355) — A7.4.5 A=01, bits[9:7]=110/111.
   bit[10]=F selects integer (0) vs .F32 (1). bit[6]=Q selects D vs Q form. */
uint8_t* PlaceNeonData2RegUnaryArith(uint8_t*      cursor,
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
    const uint32_t F     = (w >> 10) & 1u;
    const uint32_t size  = (w >> 18) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    if (size == 3u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    if (F == 1u && size != 2u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    if (Q != 0u && ((d_idx & 1u) || (m_idx & 1u))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t esize = 8u << size;
    const uint32_t regs  = Q ? 2u : 1u;

    EmitPush32(cursor, regs);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, F);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon2RegUnaryArith())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon2RegUnaryArith::HandleUnaryArithHelper));
    EmitAddRegImm32(cursor, kEsp, 28);
    return cursor;
}
