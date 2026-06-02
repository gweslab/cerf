#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_2reg_narrow.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VMOVN / VQMOVUN / VQMOVN.S / VQMOVN.U (A8.8.347 / A8.8.374) — A7.4.5
   A=10, bits[10:8]=010 with op at bits[7:6] selecting the variant. */
uint8_t* PlaceNeonData2RegNarrow(uint8_t*      cursor,
                                 DecodedInsn*  d,
                                 BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const uint32_t w     = d->immediate;
    const uint32_t op    = d->op1;  /* kMovn/kQmovun/kQmovnS/kQmovnU */
    const uint32_t Vd    = (w >> 12) & 0xFu;
    const uint32_t Vm    =  w        & 0xFu;
    const uint32_t Dbit  = (w >> 22) & 1u;
    const uint32_t Mbit  = (w >>  5) & 1u;
    const uint32_t size  = (w >> 18) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* A8.8.347 line 45623 / A8.8.374 line 48074: size==11 UND. */
    if (size == 3u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* Vm[0]==1 UND — source is Q-register, even-indexed D required. */
    if (m_idx & 1u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t esize_out = 8u << size;

    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, esize_out);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Neon2RegNarrow())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon2RegNarrow::HandleNarrowHelper));
    EmitAddRegImm32(cursor, kEsp, 20);
    return cursor;
}
