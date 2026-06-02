#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_2reg_shuffle.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VTRN / VUZP / VZIP (A8.8.420 / A8.8.422 / A8.8.423) — A7.4.5 A=10,
   bits[10:7]=0001/0010/0011. */
uint8_t* PlaceNeonData2RegShuffle(uint8_t*      cursor,
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
    const uint32_t size  = (w >> 18) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* size==11 UND per A8.8.420 line 52787 / A8.8.422 line 52953 / A8.8.423 line 53066. */
    if (size == 3u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* VUZP/VZIP additionally UND on D-form .32 per same lines (it's a
       pseudo-instruction synonym for VTRN.32 — the encoding is reserved). */
    if (op != ArmNeon2RegShuffle::kTrn && Q == 0u && size == 2u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* Q && (Vd[0]||Vm[0]) UND — all three ops. */
    if (Q != 0u && ((d_idx & 1u) || (m_idx & 1u))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t esize = 8u << size;

    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, Q);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon2RegShuffle())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon2RegShuffle::HandleShuffleHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
