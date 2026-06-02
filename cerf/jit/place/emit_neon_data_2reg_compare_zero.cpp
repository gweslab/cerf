#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_2reg_compare_zero.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VCEQ / VCGT / VCGE / VCLE / VCLT immediate #0 — A7.4.5 A=01, F-bit
   discriminates integer (F=0) vs .F32 (F=1). */
uint8_t* PlaceNeonData2RegCompareZero(uint8_t*      cursor,
                                      DecodedInsn*  d,
                                      BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const uint32_t w     = d->immediate;
    const uint32_t op    = d->op1;
    const uint32_t Vd    = (w >> 12) & 0xFu;
    const uint32_t Vm    =  w        & 0xFu;
    const uint32_t Dbit  = (w >> 22) & 1u;
    const uint32_t Mbit  = (w >>  5) & 1u;
    const uint32_t Q     = (w >>  6) & 1u;
    const uint32_t F     = (w >> 10) & 1u;
    const uint32_t size  = (w >> 18) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* A8.8.292 line 40255 / A8.8.294 line 40475 / A8.8.296 line 40694 /
       A8.8.298 line 40790 / A8.8.301 line 40964 — common UND form. */
    if (size == 3u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    if (F == 1u && size != 2u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    if (Q != 0u && ((d_idx & 1u) || (m_idx & 1u))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t esize = 8u << size;
    const uint32_t regs  = Q ? 2u : 1u;

    EmitPush32(cursor, regs);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, F);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon2RegCompareZero())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon2RegCompareZero::HandleCompareZeroHelper));
    EmitAddRegImm32(cursor, kEsp, 28);
    return cursor;
}
