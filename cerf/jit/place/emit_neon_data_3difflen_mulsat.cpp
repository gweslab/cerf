#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_3difflen.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* 3-reg-different-length Saturating Doubling Multiply Long family
   (A8.8.371 VQDMLAL/VQDMLSL T1/A1, A8.8.373 VQDMULL T1/A1). D op D -> Q,
   signed only, saturating with sticky FPSCR.QC. */
uint8_t* PlaceNeonData3DiffLenMulSat(uint8_t*      cursor,
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
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* U must be 0 — VQDMLAL/VQDMLSL/VQDMULL are signed-only encodings.
       A7.4.2: "Other encodings in this space are UNDEFINED". */
    if (U != 0u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* size==00 and size==11 both UND per A8.8.371 line 47730 and
       A8.8.373 line 47965. Valid: size in {01, 10}. */
    if (size == 0u || size == 3u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* Vd<0>==1 UND (output Q-reg at d>>1). */
    if ((d_idx & 1u) != 0u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t esize = 8u << size;

    EmitPush32(cursor, esize);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, n_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon3DiffLen())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon3DiffLen::HandleMulLongSatHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
