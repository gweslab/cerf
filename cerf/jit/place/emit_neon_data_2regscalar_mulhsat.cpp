#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_2regscalar.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* 2-reg-and-scalar Saturating Doubling Multiply Returning High Half
   (A8.8.372 VQDMULH / A8.8.376 VQRDMULH, T2/A2). Same-length output;
   bit[24]=Q selects D vs Q form. Signed only (no U bit in this encoding). */
uint8_t* PlaceNeonData2RegScalarMulhSat(uint8_t*      cursor,
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
    const uint32_t Q     = (w >> 24) & 1u;
    const uint32_t size  = (w >> 20) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t n_idx = (Nbit << 4) | Vn;

    /* size==00 || size==11 UND per A8.8.372 lines 47868-47869 /
       A8.8.376 lines 48265-48266. */
    if (size == 0u || size == 3u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* Q=1 with odd Vd or Vn UND per A8.8.372 line 47870 / A8.8.376 line 48267. */
    if (Q != 0u && ((d_idx & 1u) || (n_idx & 1u))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

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

    const uint32_t regs = Q ? 2u : 1u;

    EmitPush32(cursor, regs);
    EmitPush32(cursor, index);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, n_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon2RegScalar())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon2RegScalar::HandleScalarMulhSatHelper));
    EmitAddRegImm32(cursor, kEsp, 32);
    return cursor;
}
