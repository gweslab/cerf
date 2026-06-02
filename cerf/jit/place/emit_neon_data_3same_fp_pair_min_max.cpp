#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_3same_fp_pair_min_max.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VPMAX / VPMIN (floating-point) — A8.8.366, opc=1111 C=0 U=1. */
uint8_t* PlaceNeonData3SameFpPairMinMax(uint8_t*      cursor,
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

    /* A8.8.366 line 47284: sz==1 || Q==1 UND. */
    if (sz != 0u || Q != 0u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, n_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon3SameFpPairMinMax())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon3SameFpPairMinMax::Handle3SameFpPairMinMaxHelper));
    EmitAddRegImm32(cursor, kEsp, 20);
    return cursor;
}
