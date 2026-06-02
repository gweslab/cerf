#include <cstdint>

#include "../arm_jit.h"
#include "../arm_neon_shift_imm.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* VSHLL T2/A2 (A8.8.397, line 50311 "Or TRUE without change of functionality"
   — routed through kSiShllS, sign-extension is bit-equivalent at shift=esize). */
uint8_t* PlaceNeonData2RegWiden(uint8_t*      cursor,
                                DecodedInsn*  d,
                                BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const uint32_t w     = d->immediate;
    const uint32_t Vd    = (w >> 12) & 0xFu;
    const uint32_t Vm    =  w        & 0xFu;
    const uint32_t Dbit  = (w >> 22) & 1u;
    const uint32_t Mbit  = (w >>  5) & 1u;
    const uint32_t size  = (w >> 18) & 3u;
    const uint32_t d_idx = (Dbit << 4) | Vd;
    const uint32_t m_idx = (Mbit << 4) | Vm;

    /* A8.8.397 line 50309: size==11 || Vd[0]==1 UND. */
    if (size == 3u || (d_idx & 1u)) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t esize        = 8u << size;
    const uint32_t shift_amount = esize;
    const uint32_t op_sel       = ArmNeonShiftImm::kSiShllS;

    EmitPush32(cursor, shift_amount);
    EmitPush32(cursor, esize);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op_sel);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->NeonShiftImm())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeonShiftImm::HandleShiftImmWidenHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
