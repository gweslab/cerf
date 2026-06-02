#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_2regscalar.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* 2-reg-and-scalar Saturating Doubling Multiply Long form
   (A8.8.371 VQDMLAL/VQDMLSL T2/A2). Signed only (U=0 fixed). */
uint8_t* PlaceNeonData2RegScalarMulSat(uint8_t*      cursor,
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
    const uint32_t Nbit  = (w >> 7)  & 1u;
    const uint32_t Mbit  = (w >> 5)  & 1u;
    const uint32_t U     = (w >> 24) & 1u;
    const uint32_t size  = (w >> 20) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t n_idx = (Nbit << 4) | Vn;

    /* U fixed 0 in this encoding; A7.4.2 "Other encodings UNDEFINED". */
    if (U != 0u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* size==00 / size==11 UND per A8.8.371 line 47730. */
    if (size == 0u || size == 3u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* Vd<0>==1 UND (output Q-reg at d>>1). */
    if ((d_idx & 1u) != 0u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    /* Scalar extraction per A8.8.371 line 47751-47752. */
    uint32_t esize, m_idx, index;
    if (size == 1u) {
        esize = 16u;
        m_idx = Vm & 0x7u;
        index = (Mbit << 1) | ((Vm >> 3) & 1u);
    } else {
        esize = 32u;
        m_idx = Vm;
        index = Mbit;
    }

    EmitPush32(cursor, index);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, n_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon2RegScalar())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon2RegScalar::HandleScalarMulLongSatHelper));
    EmitAddRegImm32(cursor, kEsp, 28);
    return cursor;
}
