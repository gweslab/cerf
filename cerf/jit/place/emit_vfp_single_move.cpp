#include <cstddef>
#include <cstdint>

#include "../arm_cpu.h"
#include "../arm_jit.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* Move between ARM core register d->rd and VFP single register index `sn`,
   d->l selects direction. Rt=R15 on a read does the FMRS/VMRS NZCV-to-APSR
   transfer. Shared by EmitVfpSingleMove (cp10 VMOV Sn<->Rt) and the cp11
   esize-32 scalar VMOV (FMRDL/FMRDH) in EmitVfpRegisterTransfer. */
uint8_t* EmitVfpSingleMoveIdx(uint8_t*      cursor,
                              DecodedInsn*  d,
                              BlockContext* ctx,
                              uint32_t      sn) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const int32_t sn_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, vfp_d) + sn * 4u);
    const int32_t rt_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4u);

    if (d->l) {
        if (d->rd == 15) {
            /* Rt=R15 — FPSCR-style NZCV transfer to APSR. */
            EmitPushBaseDisp32(cursor, kStateReg, sn_disp);
            EmitPush32(cursor,
                static_cast<uint32_t>(
                    reinterpret_cast<uintptr_t>(jit->Cpu())));
            EmitCall(cursor, reinterpret_cast<void*>(
                &ArmCpu::UpdateNzcvOnlyHelper));
            EmitAddRegImm32(cursor, kEsp, 8);
            return cursor;
        }
        EmitMovRegBaseDisp32(cursor, kEax, kStateReg, sn_disp);
        EmitMovBaseDisp32Reg(cursor, kStateReg, rt_disp, kEax);
        return cursor;
    }

    EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rt_disp);
    EmitMovBaseDisp32Reg(cursor, kStateReg, sn_disp, kEax);
    return cursor;
}

/* VMOV Sn <-> Rt — cp10 single 32-bit transfer. Sn = Vn:N = (Vn<<1)|N
   (A8.6.341/342); the DP layout (N<<4)|Vn aliases odd single regs. */
uint8_t* EmitVfpSingleMove(uint8_t*      cursor,
                           DecodedInsn*  d,
                           BlockContext* ctx) {
    const uint32_t sn = ((d->crn & 0xFu) << 1) | ((d->cp >> 2) & 1u);
    return EmitVfpSingleMoveIdx(cursor, d, ctx, sn);
}
