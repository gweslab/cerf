#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_sat.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* Saturating narrowing right shift (A8.8.381 VQSHRN/VQSHRUN truncating,
   A8.8.378 VQRSHRN/VQRSHRUN rounding). `esize` is the OUTPUT size;
   source is 2*esize. */
uint8_t* PlaceNeonShiftImmNarrowSat(uint8_t*      cursor,
                                    DecodedInsn*  d,
                                    BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const uint32_t w     = d->immediate;
    const uint32_t op    = d->op1;
    const uint32_t Vd    = (w >> 12) & 0xFu;
    const uint32_t Vm    =  w        & 0xFu;
    const uint32_t Dbit  = (w >> 22) & 1u;
    const uint32_t Mbit  = (w >> 5)  & 1u;
    const uint32_t L_bit = (w >> 7)  & 1u;
    const uint32_t imm6  = (w >> 16) & 0x3Fu;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* bit7 (L) is fixed 0 in this region; Vm<0> must be 0 (Qm source).
       bit6 disambiguates rounding vs truncating and is resolved by the
       decoder via the op selector. */
    if (L_bit != 0u || (m_idx & 1u) != 0u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    uint32_t esize, shift_amount;
    if (imm6 & 0x20u) {
        esize        = 32u;
        shift_amount = 64u - imm6;
    } else if (imm6 & 0x10u) {
        esize        = 16u;
        shift_amount = 32u - imm6;
    } else if (imm6 & 0x08u) {
        esize        = 8u;
        shift_amount = 16u - imm6;
    } else {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    EmitPush32(cursor, shift_amount);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->NeonSat())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeonSat::HandleShiftImmNarrowSatHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
