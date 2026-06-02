#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_2regscalar.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* 2-reg-and-scalar Long form (A8.8.338 T2/A2 VMLAL/VMLSL by scalar).
   D op scalar -> Q; bit[24]=U selects sign/zero extend before mul. */
uint8_t* PlaceNeonData2RegScalarLong(uint8_t*      cursor,
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

    /* size==00 || size==11 UND (A8.8.338 line 44838-44839). */
    if (size == 0u || size == 3u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* Vd<0>==1 UND (output Q-reg at d>>1). */
    if ((d_idx & 1u) != 0u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    /* Same scalar extraction as same-length form (A8.8.338 line 44842-44843):
       esize=16 → m=Vm[2:0], index=M:Vm[3]; esize=32 → m=Vm, index=M. */
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

    EmitPush32(cursor, U);
    EmitPush32(cursor, index);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, n_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon2RegScalar())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon2RegScalar::HandleScalarMlsMlaLongHelper));
    EmitAddRegImm32(cursor, kEsp, 32);
    return cursor;
}
