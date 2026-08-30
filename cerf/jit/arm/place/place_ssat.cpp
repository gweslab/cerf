#include <cstddef>

#include "../cpu_state.h"
#include "../place_fns.h"
#include "../../x86_emit_alu.h"

namespace {

constexpr int32_t GprDisp(uint32_t n) {
    return static_cast<int32_t>(offsetof(ArmCpuState, gprs) + n * 4u);
}

constexpr int32_t CpsrDisp() {
    return static_cast<int32_t>(offsetof(ArmCpuState, cpsr));
}

}  /* namespace */

/* DDI 0406C.c A8.8.193 SSAT A1 (p. A8-653): "(result, sat) =
   SignedSatQ(SInt(operand), saturate_to)", SignedSatQ (p. A2-44) clamping to
   2^(N-1)-1 / -(2^(N-1)), APSR.Q bit[27] (p. B1-1148). ASR #32 (imm5 == 0)
   replicates bit[31]; x86 SAR masks its count to 5 bits (SDM Vol. 2B 4-600). */
uint8_t* PlaceSsat(uint8_t* cursor, DecodedInsn* d, BlockContext*) {
    using namespace x86;

    EmitMovRegBaseDisp32(cursor, kEax, kStateReg, GprDisp(d->rn));

    if (d->op1 == kSrLsl) {
        if (d->rs != 0u) {
            EmitShlReg32Imm(cursor, kEax, static_cast<uint8_t>(d->rs));
        }
    } else {
        EmitSarReg32Imm(cursor, kEax,
                        static_cast<uint8_t>(d->rs >= 32u ? 31u : d->rs));
    }

    if (d->immediate < 32u) {
        const uint32_t bound = 1u << (d->immediate - 1u);
        const uint32_t hi    = bound - 1u;
        const uint32_t lo    = 0u - bound;

        EmitCmpRegImm32(cursor, kEax, hi);
        uint8_t* below_hi = EmitJleLabel(cursor);
        EmitMovRegImm32      (cursor, kEax, hi);
        EmitOrBaseDisp32Imm32(cursor, kStateReg, CpsrDisp(), 1u << 27);
        FixupLabel(below_hi, cursor);

        EmitCmpRegImm32(cursor, kEax, lo);
        uint8_t* above_lo = EmitJgeLabel(cursor);
        EmitMovRegImm32      (cursor, kEax, lo);
        EmitOrBaseDisp32Imm32(cursor, kStateReg, CpsrDisp(), 1u << 27);
        FixupLabel(above_lo, cursor);
    }

    EmitMovBaseDisp32Reg(cursor, kStateReg, GprDisp(d->rd), kEax);
    return cursor;
}
