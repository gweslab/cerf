#include <cstddef>
#include <cstdint>

#include "../arm_jit.h"
#include "../coproc_emitter.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* MCRR/MRRC cp_num=11 with bits[7:6:4]=001 encodes VMOV between
   two ARM core registers and a doubleword extension register
   (DDI 0406C §A8.8.345). m = M:Vm. */

uint8_t* PlaceCoprocExtension(uint8_t*      cursor,
                              DecodedInsn*  d,
                              BlockContext* ctx) {
    using namespace x86;

    cursor = PlaceCoprocessorPermissionCheck(cursor, d, ctx);

    if (d->cp_num != 11u) {
        return ctx->jit->Coproc()->EmitRegisterTransferDouble(cursor, d, ctx);
    }

    const uint32_t opc1 = (d->offset >> 4) & 0xFu;
    if ((opc1 & 0xDu) != 0x1u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t M  = (opc1 >> 1) & 1u;
    const uint32_t Vm = d->offset & 0xFu;
    const uint32_t m  = (M << 4) | Vm;
    const uint32_t Rt  = d->crd;
    const uint32_t Rt2 = d->rn;
    const bool to_arm  = d->x1 != 0u;

    /* Writing GPR slot 15 via vfp_d-store bypasses the JIT's
       r15_modified branch-resolve and corrupts block flow. */
    if (Rt == 15u || Rt2 == 15u) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }
    if (to_arm && Rt == Rt2) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const int32_t rt_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + Rt  * 4u);
    const int32_t rt2_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + Rt2 * 4u);
    const int32_t d_lo_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, vfp_d) + m * 8u);
    const int32_t d_hi_disp = d_lo_disp + 4;

    if (to_arm) {
        EmitMovRegBaseDisp32(cursor, kEax, kStateReg, d_lo_disp);
        EmitMovBaseDisp32Reg(cursor, kStateReg, rt_disp,  kEax);
        EmitMovRegBaseDisp32(cursor, kEax, kStateReg, d_hi_disp);
        EmitMovBaseDisp32Reg(cursor, kStateReg, rt2_disp, kEax);
    } else {
        EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rt_disp);
        EmitMovBaseDisp32Reg(cursor, kStateReg, d_lo_disp, kEax);
        EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rt2_disp);
        EmitMovBaseDisp32Reg(cursor, kStateReg, d_hi_disp, kEax);
    }
    return cursor;
}
