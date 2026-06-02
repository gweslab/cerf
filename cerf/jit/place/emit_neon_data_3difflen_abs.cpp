#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_3difflen.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* 3-reg-different-length absolute-difference Long family
   (A8.8.277 VABAL T2/A2, A8.8.278 VABDL T2/A2). D op D -> Q. */
uint8_t* PlaceNeonData3DiffLenAbs(uint8_t*      cursor,
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
    const uint32_t size  = (w >> 20) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t n_idx = (Nbit << 4) | Vn;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* size==11 UND (A8.8.277 line 38959, A8.8.278 line 39073). */
    if (size == 3u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* Vd<0>==1 UND (output Q-reg at d>>1; A8.8.277 line 38960, A8.8.278
       line 39074). No constraint on Vn or Vm — both are D-regs. */
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
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon3DiffLen::HandleAbsDiffLongHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
