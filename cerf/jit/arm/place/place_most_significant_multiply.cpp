#include <cstddef>

#include "../cpu_state.h"
#include "../place_fns.h"
#include "../../x86_emit_alu.h"

namespace {

constexpr int32_t GprDisp(uint32_t n) {
    return static_cast<int32_t>(offsetof(ArmCpuState, gprs) + n * 4u);
}

}  /* namespace */

/* DDI 0406C.c Table A5-20 (p. A5-213) op1 101; A1 operations SMMLA p. A8-637
   "result = (SInt(R[a]) << 32) + SInt(R[n]) * SInt(R[m])", SMMLS A8-639
   "result = (SInt(R[a]) << 32) - SInt(R[n]) * SInt(R[m])", SMMUL A8-641;
   "if round then result = result + 0x80000000; R[d] = result<63:32>". */
uint8_t* PlaceMostSignificantMultiply(uint8_t* cursor, DecodedInsn* d,
                                      BlockContext*) {
    using namespace x86;

    EmitMovRegBaseDisp32(cursor, kEax, kStateReg, GprDisp(d->rn));
    EmitMovRegBaseDisp32(cursor, kEcx, kStateReg, GprDisp(d->rm));
    EmitImulReg32       (cursor, kEcx);

    if (d->n != 0u) {
        EmitNegReg32   (cursor, kEdx);
        EmitNegReg32   (cursor, kEax);
        EmitSbbRegImm32(cursor, kEdx, 0u);
    }
    if (d->op1 != 0u) {
        EmitAddRegBaseDisp32(cursor, kEdx, kStateReg, GprDisp(d->rs));
    }
    if (d->u != 0u) {
        EmitAddRegImm32(cursor, kEax, 0x80000000u);
        EmitAdcRegImm32(cursor, kEdx, 0u);
    }
    EmitMovBaseDisp32Reg(cursor, kStateReg, GprDisp(d->rd), kEdx);
    return cursor;
}
