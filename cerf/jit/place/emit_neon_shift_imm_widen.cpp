#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_shift_imm.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* Widening left shift family: VSHLL T1/A1 (A8.8.397). `esize` is the
   INPUT element size; output is a Q register with 2*esize elements. */
uint8_t* PlaceNeonShiftImmWiden(uint8_t*      cursor,
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

    /* L=0 fixed in T1/A1 encoding (A8.8.397 line 50281); Vd<0> == 1 is
       UNDEFINED because the output is the Q register at d>>1. */
    if (L_bit != 0u || (d_idx & 1u) != 0u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    /* esize/shift from imm6 per A8.8.397 case table at line 50289. */
    uint32_t esize, shift_amount;
    if (imm6 & 0x20u) {
        esize        = 32u;
        shift_amount = imm6 - 32u;
    } else if (imm6 & 0x10u) {
        esize        = 16u;
        shift_amount = imm6 - 16u;
    } else if (imm6 & 0x08u) {
        esize        = 8u;
        shift_amount = imm6 - 8u;
    } else {
        /* imm6 = 000xxx is the 1-reg-modified-immediate region (gated by
           the decoder, but defensive UND in case of stray routing). */
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    EmitPush32(cursor, shift_amount);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->NeonShiftImm())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeonShiftImm::HandleShiftImmWidenHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
