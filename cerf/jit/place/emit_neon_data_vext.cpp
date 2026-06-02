#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_vext.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VEXT — A8.8.316, U=0, bit23=1, bits[21:20]=11, bit[4]=0. */
uint8_t* PlaceNeonDataVext(uint8_t*      cursor,
                           DecodedInsn*  d,
                           BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const uint32_t w     = d->immediate;
    const uint32_t Vn    = (w >> 16) & 0xFu;
    const uint32_t Vd    = (w >> 12) & 0xFu;
    const uint32_t imm4  = (w >>  8) & 0xFu;
    const uint32_t Vm    =  w        & 0xFu;
    const uint32_t Dbit  = (w >> 22) & 1u;
    const uint32_t Nbit  = (w >>  7) & 1u;
    const uint32_t Mbit  = (w >>  5) & 1u;
    const uint32_t Q     = (w >>  6) & 1u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t n_idx = (Nbit << 4) | Vn;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* A8.8.316 line 42270: Q==1 with odd reg index UND. */
    if (Q != 0u && ((d_idx & 1u) || (n_idx & 1u) || (m_idx & 1u))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* A8.8.316 line 42271: Q==0 with imm4<3>==1 UND (imm4 must be 0..7
       for doubleword; imm4 bytes from the LSB of the 16-byte
       concatenation must fit in the 8-byte result). */
    if (Q == 0u && ((imm4 >> 3) & 1u)) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    EmitPush32(cursor, Q);
    EmitPush32(cursor, imm4);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, n_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->NeonVext())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeonVext::HandleVextHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
