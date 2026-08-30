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

constexpr uint32_t kAccNone = 0u;
constexpr uint32_t kAccWord = 1u;
constexpr uint32_t kAccLong = 2u;

}  /* namespace */

/* DDI 0406C.c Table A5-20 (p. A5-213) op1 000 and 100; A1 operations SMLAD
   p. A8-623, SMUAD A8-643, SMLSD A8-633, SMUSD A8-651, SMLALD A8-629,
   SMLSLD A8-635. SMUSD "Signed overflow cannot occur" and the long forms
   "wrap around modulo 2^64"; the rest set APSR.Q, bit[27] (B1-1148). */
uint8_t* PlaceDualMultiply(uint8_t* cursor, DecodedInsn* d, BlockContext*) {
    using namespace x86;

    EmitMovRegBaseDisp32(cursor, kEax, kStateReg, GprDisp(d->rn));
    EmitMovRegBaseDisp32(cursor, kEcx, kStateReg, GprDisp(d->rm));
    if (d->u != 0u) {
        EmitRorReg32Imm(cursor, kEcx, 16u);
    }
    EmitMovRegReg      (cursor, kEdi, kEax);
    EmitMovRegReg      (cursor, kEdx, kEcx);
    EmitMovsxReg32Reg16(cursor, kEax, kEax);
    EmitMovsxReg32Reg16(cursor, kEcx, kEcx);
    EmitImulReg32Reg32 (cursor, kEax, kEcx);
    EmitSarReg32Imm    (cursor, kEdi, 16u);
    EmitSarReg32Imm    (cursor, kEdx, 16u);
    EmitImulReg32Reg32 (cursor, kEdi, kEdx);

    EmitCdq        (cursor);
    EmitMovRegReg  (cursor, kEcx, kEdi);
    EmitSarReg32Imm(cursor, kEcx, 31u);
    if (d->n != 0u) {
        EmitSubReg32Reg32(cursor, kEax, kEdi);
        EmitSbbReg32Reg32(cursor, kEdx, kEcx);
    } else {
        EmitAddReg32Reg32(cursor, kEax, kEdi);
        EmitAdcReg32Reg32(cursor, kEdx, kEcx);
    }

    if (d->op1 == kAccLong) {
        EmitAddRegBaseDisp32(cursor, kEax, kStateReg, GprDisp(d->rs));
        EmitAdcRegBaseDisp32(cursor, kEdx, kStateReg, GprDisp(d->rd));
        EmitMovBaseDisp32Reg(cursor, kStateReg, GprDisp(d->rs), kEax);
        EmitMovBaseDisp32Reg(cursor, kStateReg, GprDisp(d->rd), kEdx);
        return cursor;
    }

    if (d->op1 == kAccWord) {
        EmitMovRegBaseDisp32(cursor, kEdi, kStateReg, GprDisp(d->rs));
        EmitMovRegReg       (cursor, kEcx, kEdi);
        EmitSarReg32Imm     (cursor, kEcx, 31u);
        EmitAddReg32Reg32   (cursor, kEax, kEdi);
        EmitAdcReg32Reg32   (cursor, kEdx, kEcx);
    }

    const bool sets_q = !(d->op1 == kAccNone && d->n != 0u);
    if (sets_q) {
        EmitMovRegReg  (cursor, kEcx, kEax);
        EmitSarReg32Imm(cursor, kEcx, 31u);
        EmitXorRegReg  (cursor, kEcx, kEdx);
        uint8_t* in_range = EmitJzLabel(cursor);
        EmitOrBaseDisp32Imm32(cursor, kStateReg, CpsrDisp(), 1u << 27);
        FixupLabel(in_range, cursor);
    }
    EmitMovBaseDisp32Reg(cursor, kStateReg, GprDisp(d->rd), kEax);
    return cursor;
}
