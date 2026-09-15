#include <cstdint>

#include "../arm_emit_services.h"
#include "../arm_neon_2reg_cvt_int_fp.h"
#include "../decoded_insn.h"
#include "../place_fns.h"
#include "../../x86_emit_alu.h"

/* VCVT int↔fp Advanced SIMD (A8.8.305) - A7.4.5 A=11, bits[10:9]=11,
   bits[8:7]=op. Also handles immediate-scaled VCVT (DDI 0406C.d A8.8.308). */
uint8_t* PlaceNeonData2RegCvtIntFp(uint8_t*      cursor,
                                   DecodedInsn*  d,
                                   BlockContext* ctx) {
    using namespace x86;
    ArmEmitServices* emit = ctx->emit;

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
    const bool fixed = ((w >> 8) & 0xEu) == 0xEu;
    // DDI 0406C.d corrects the older edition's erroneous extra subtraction.
    const uint32_t frac_bits = fixed ? 64u - ((w >> 16) & 63u) : 0u;

    /* A8.8.305 line 41310: size!=10 UND. */
    if ((!fixed && size != 2u) || (fixed && (frac_bits > 32u || (w & 0x80u)))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    /* A8.8.305 line 41309. */
    if (Q != 0u && ((d_idx & 1u) || (m_idx & 1u))) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t regs = Q ? 2u : 1u;

    EmitPush32(cursor, frac_bits);
    EmitPush32(cursor, regs);
    EmitPush32(cursor, m_idx);
    EmitPush32(cursor, d_idx);
    EmitPush32(cursor, op);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(emit->Neon2RegCvtIntFp())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmNeon2RegCvtIntFp::HandleCvtIntFpHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
