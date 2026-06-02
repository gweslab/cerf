#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_3same_fp_recip_step.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VRECPS / VRSQRTS — A8.8.385 / A8.8.392, opc=1111 C=1 U=0. bit[21]
   selects RECPS (0) / RSQRTS (1). */
uint8_t* PlaceNeonData3SameFpRecipStep(uint8_t*      cursor,
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

    /* A8.8.385 line 49177 / A8.8.392 line 49840: sz==1 UND. */
    if (sz != 0u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* A8.8.385 line 49176 / A8.8.392 line 49839: Q==1 with odd reg index UND. */
    if (Q != 0u && ((d_idx & 1u) || (n_idx & 1u) || (m_idx & 1u))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t regs = Q ? 2u : 1u;

    EmitPush32(cursor, regs);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, n_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon3SameFpRecipStep())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon3SameFpRecipStep::Handle3SameFpRecipStepHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
