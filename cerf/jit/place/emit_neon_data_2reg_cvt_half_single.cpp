#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_2reg_cvt_half_single.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VCVT half↔single Advanced SIMD (A8.8.310) — A7.4.5 A=10, bits[10:7]=11x0
   with bit[6]=0. bit[8]=op selects direction (0=single→half, 1=half→single). */
uint8_t* PlaceNeonData2RegCvtHalfSingle(uint8_t*      cursor,
                                        DecodedInsn*  d,
                                        BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const uint32_t w     = d->immediate;
    const uint32_t op    = d->op1;  /* kSingleToHalf or kHalfToSingle */
    const uint32_t Vd    = (w >> 12) & 0xFu;
    const uint32_t Vm    =  w        & 0xFu;
    const uint32_t Dbit  = (w >> 22) & 1u;
    const uint32_t Mbit  = (w >>  5) & 1u;
    const uint32_t size  = (w >> 18) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* A8.8.310 line 41795: size != 01 UND. */
    if (size != 1u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* A8.8.310 line 41796: half_to_single && Vd[0]==1 UND (dst is Q-reg). */
    if (op == ArmNeon2RegCvtHalfSingle::kHalfToSingle && (d_idx & 1u)) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* A8.8.310 line 41797: !half_to_single && Vm[0]==1 UND (src is Q-reg). */
    if (op == ArmNeon2RegCvtHalfSingle::kSingleToHalf && (m_idx & 1u)) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon2RegCvtHalfSingle())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon2RegCvtHalfSingle::HandleCvtHalfSingleHelper));
    EmitAddRegImm32(cursor, kEsp, 16);
    return cursor;
}
