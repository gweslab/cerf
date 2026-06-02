#include "../../jit/coproc_emitter.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>

#include "../../core/cerf_emulator.h"
#include "../../jit/arm_jit.h"
#include "../../jit/arm_mmu_state.h"
#include "../../jit/cpu_state.h"
#include "../../jit/place_fns.h"
#include "../../jit/x86_emit.h"
#include "../../boards/board_detector.h"

namespace {

class XscaleCoprocEmitter : public CoprocEmitter {
public:
    using CoprocEmitter::CoprocEmitter;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }

    uint8_t* EmitRegisterTransfer(uint8_t*      cursor,
                                  DecodedInsn*  d,
                                  BlockContext* ctx) override {
        if (d->cp_num == 15) {
            /* CPAR (Coprocessor Access Register) — XScale §7.2.15: cp15
               c15, CRm=c1, opc2=0. Shared cp15 dispatch UNDs c15 (boot
               hangs on the UND), so handle here. Backed by ArmMmuState::
               coprocessor_access, unused on XScale unless HasCp15V6(). */
            if (d->crn == 15 && d->crm == 1 && d->cp == 0 && d->cp_opc == 0) {
                using namespace x86;
                const int32_t rd_disp = static_cast<int32_t>(
                    offsetof(ArmCpuState, gprs) + d->rd * 4u);
                const int32_t cpar_disp = static_cast<int32_t>(
                    offsetof(ArmMmuState, coprocessor_access));
                if (d->l) {
                    EmitMovRegBaseDisp32(cursor, kEax, kMmuReg, cpar_disp);
                    EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
                } else {
                    EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
                    EmitMovBaseDisp32Reg(cursor, kMmuReg, cpar_disp, kEax);
                }
                return cursor;
            }
            return EmitCp15RegisterTransfer(cursor, d, ctx);
        }
        if (d->cp_num == 14 && d->cp_opc == 0 && d->crm == 0 && d->cp == 0) {
            using namespace x86;
            const int32_t rd_disp = static_cast<int32_t>(
                offsetof(ArmCpuState, gprs) + d->rd * 4u);

            /* PWRMODE (CRn=c7) — XScale Core Dev Manual Table 7-23. Writes
               request a low-power mode (M field != 0); during ACTIVE the
               OAL idle loop writes it to halt the core until the next
               interrupt. Read always returns 0 in the M field. */
            if (d->crn == 7) {
                if (d->l) {
                    EmitMovBaseDisp32Imm32(cursor, kStateReg, rd_disp, 0u);
                } else {
                    EmitMovRegImm32(cursor, kEcx,
                        static_cast<uint32_t>(
                            reinterpret_cast<uintptr_t>(ctx->jit)));
                    EmitCall(cursor,
                        reinterpret_cast<void*>(&ArmJit::WfiHelper));
                }
                return cursor;
            }

            /* CCLKCFG (CRn=c6) — XScale Core Dev Manual Table 7-25. The
               frequency change completes instantly under emulation (no PLL
               relock), so a write has no retained state; reads return 0
               (active, non-turbo). */
            if (d->crn == 6) {
                if (d->l) {
                    EmitMovBaseDisp32Imm32(cursor, kStateReg, rd_disp, 0u);
                }
                return cursor;
            }
            /* Any other CP14 register (e.g. the c0-c5 performance monitor) is a
               real XScale instruction we have not emitted — loud FATAL, never UND. */
            return EmitCoprocUnimplementedFatal(cursor, d, ctx);
        }
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    uint8_t* EmitDataTransfer(uint8_t*      cursor,
                              DecodedInsn*  d,
                              BlockContext* ctx) override {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    uint8_t* EmitDataOperation(uint8_t*      cursor,
                               DecodedInsn*  d,
                               BlockContext* ctx) override {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    /* MCRR/MRRC — XScale supports these only to CP0, the DSP 40-bit
       accumulator acc0 (MAR/MRA, Core Dev Manual §2.3.1 Table 2-6); any
       other coprocessor UNDs (§2.2.4). */
    uint8_t* EmitRegisterTransferDouble(uint8_t*      cursor,
                                        DecodedInsn*  d,
                                        BlockContext* ctx) override {
        using namespace x86;
        if (d->cp_num != 0u) {
            return EmitRaiseUndAndReturn(cursor, d, ctx);
        }

        const uint32_t rdlo = d->crd;       /* RdLo (bits[15:12]) */
        const uint32_t rdhi = d->rn;        /* RdHi (bits[19:16]) */
        const bool to_arm   = d->x1 != 0u;  /* L=1 → MRRC = MRA (read acc0) */

        /* Writing R15 bypasses the JIT branch-resolve; on MRA a shared
           RdLo/RdHi register makes the result unpredictable. */
        if (rdlo == 15u || rdhi == 15u || (to_arm && rdlo == rdhi)) {
            return EmitRaiseUndAndReturn(cursor, d, ctx);
        }

        /* CP0 access is gated by CPAR bit0 (§2.3.1 / §7.2.15): when clear
           the access UNDs so the OS lazy-enable handler grants it and
           retries. TEST dword [coprocessor_access], 1 ; JNZ enabled. */
        const int32_t cpar_disp = static_cast<int32_t>(
            offsetof(ArmMmuState, coprocessor_access));
        Emit8(cursor, 0xF7);
        EmitModRmReg(cursor, 2, kMmuReg, 0);
        Emit32(cursor, static_cast<uint32_t>(cpar_disp));
        Emit32(cursor, 1u);
        uint8_t* enabled = EmitJnzLabel(cursor);
        cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
        FixupLabel(enabled, cursor);

        const int32_t rdlo_disp = static_cast<int32_t>(
            offsetof(ArmCpuState, gprs) + rdlo * 4u);
        const int32_t rdhi_disp = static_cast<int32_t>(
            offsetof(ArmCpuState, gprs) + rdhi * 4u);
        const int32_t acc_lo_disp =
            static_cast<int32_t>(offsetof(ArmCpuState, acc0));
        const int32_t acc_hi_disp = acc_lo_disp + 4;

        if (to_arm) {
            /* MRA: RdLo = acc0[31:0]; RdHi = sign_extend(acc0[39:32]). */
            EmitMovRegBaseDisp32(cursor, kEax, kStateReg, acc_lo_disp);
            EmitMovBaseDisp32Reg(cursor, kStateReg, rdlo_disp, kEax);
            EmitMovsxByteRegBaseDisp32(cursor, kEax, kStateReg, acc_hi_disp);
            EmitMovBaseDisp32Reg(cursor, kStateReg, rdhi_disp, kEax);
        } else {
            /* MAR: acc0[31:0] = RdLo; acc0[39:32] = RdHi[7:0]. */
            EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rdlo_disp);
            EmitMovBaseDisp32Reg(cursor, kStateReg, acc_lo_disp, kEax);
            EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rdhi_disp);
            EmitMovBaseDisp32Byte(cursor, kStateReg, acc_hi_disp, kAl);
        }
        return cursor;
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(XscaleCoprocEmitter, CoprocEmitter);
