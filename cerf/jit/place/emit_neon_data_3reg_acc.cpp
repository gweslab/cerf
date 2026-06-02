#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* 3-reg-same accumulate ops: d = f(d_old, n*m). Encoding (VMLA/VMLS,
   A8.8.336): opc=1001, C=0, bit24=op (MLA=0/MLS=1); op selector in
   d->op1 (ArmNeon::kAcc*). */
uint8_t* PlaceNeonData3SameAcc(uint8_t*      cursor,
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
    const uint32_t Q     = (w >> 6)  & 1u;
    const uint32_t size  = (w >> 20) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t n_idx = (Nbit << 4) | Vn;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    if (Q && ((d_idx & 1u) || (n_idx & 1u) || (m_idx & 1u))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* VMLA/VMLS have no I64 element form (A8.8.336). */
    if (size == 3u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t esize = 8u << size;
    const uint32_t regs  = Q ? 2u : 1u;

    EmitPush32(cursor, regs);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, n_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon::HandleSimd3SameAccHelper));
    EmitAddRegImm32(cursor, kEsp, 28);
    return cursor;
}
