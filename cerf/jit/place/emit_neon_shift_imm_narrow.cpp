#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_shift_imm.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* Narrowing right shift family: VSHRN (A8.8.399) truncating, VRSHRN
   (A8.8.390) rounding. `esize` is the OUTPUT size; source is 2*esize. */
uint8_t* PlaceNeonShiftImmNarrow(uint8_t*      cursor,
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

    /* bit7 (L) is fixed 0 for VSHRN/VRSHRN; bit6 disambiguates them and is
       resolved by the decoder. Vm<0> must be 0 (Qm source). */
    if (L_bit != 0u || (m_idx & 1u) != 0u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    /* Output esize from imm6 (no L bit involvement here). */
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
        /* imm6 = 000xxx is the 1-reg-modified-immediate region. */
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    EmitPush32(cursor, shift_amount);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->NeonShiftImm())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeonShiftImm::HandleShiftImmNarrowHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
