#include <cstddef>

#include "../../core/log.h"
#include "../arm_jit.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* PlaceMRSorMSR(uint8_t*      cursor,
                       DecodedInsn*  d,
                       BlockContext* ctx) {
    using namespace x86;

    auto load_gpr = [&](uint8_t reg, uint32_t n) {
        EmitMovRegBaseDisp32(cursor, reg, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, gprs) + n * 4));
    };
    auto store_gpr = [&](uint32_t n, uint8_t reg) {
        EmitMovBaseDisp32Reg(cursor, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, gprs) + n * 4),
            reg);
    };

    const uint32_t cpu_imm =
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ctx->jit->Cpu()));

    switch (d->op1) {
    case 0:  /* MRS Rd, CPSR */
        if (d->rd == ArmGpr::kR15) {
            /* MRS with Rd=PC is UNPREDICTABLE per ddi0406c §B9.3.8
               line 103351 (encoding A1: "if d == 15 then UNPREDICTABLE").
               Raise UND rather than dispatch the unpredictable result. */
            return EmitRaiseUndAndReturn(cursor, d, ctx);
        }
        EmitPush32(cursor, cpu_imm);
        EmitCall(cursor, reinterpret_cast<void*>(&ArmCpu::GetCpsrWithFlagsHelper));
        EmitAddRegImm32(cursor, kEsp, 4);
        store_gpr(d->rd, kEax);
        break;

    case 1: { /* MSR CPSR, Rm */
        const uint32_t field_mask = ArmCpu::ComputePSRMaskValue(static_cast<int>(d->rn));
        if (field_mask == 0) break;

        if (d->rn == 8) {
            /* Flags-only fast path. */
            load_gpr(kEcx, d->rm);
            EmitPushReg(cursor, kEcx);
            EmitPush32(cursor, cpu_imm);
            EmitCall(cursor, reinterpret_cast<void*>(&ArmCpu::UpdateFlagsHelper));
            EmitAddRegImm32(cursor, kEsp, 8);
        } else {
            /* General path. */
            EmitPush32(cursor, cpu_imm);
            EmitCall(cursor, reinterpret_cast<void*>(&ArmCpu::GetCpsrWithFlagsHelper));
            EmitAddRegImm32(cursor, kEsp, 4);
            EmitPush32(cursor, cpu_imm);
            EmitPush32(cursor, field_mask);
            EmitPushBaseDisp32(cursor, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rm * 4));
            EmitPushReg(cursor, kEax);
            EmitCall(cursor, reinterpret_cast<void*>(&ArmCpu::UpdatePSRMaskHelper));
            EmitAddRegImm32(cursor, kEsp, 16);
            EmitPushReg(cursor, kEax);
            EmitPush32(cursor, cpu_imm);
            EmitCall(cursor, reinterpret_cast<void*>(&ArmCpu::UpdateCpsrWithFlagsHelper));
            EmitAddRegImm32(cursor, kEsp, 8);
        }
        break;
    }

    case 2: { /* MRS Rd, SPSR — but in user/system mode SPSR doesn't exist;
                 fall back to leaving GPRs[Rd] unchanged. */
        if (d->rd == ArmGpr::kR15) {
            /* MRS with Rd=PC is UNPREDICTABLE per ddi0406c §B9.3.8
               line 103351 (the Rd=15 rule applies to both CPSR and
               SPSR forms — the R bit just selects which source). */
            return EmitRaiseUndAndReturn(cursor, d, ctx);
        }
        /* MOV EAX, [ESI + cpsr] */
        EmitMovRegBaseDisp32(cursor, kEax, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, cpsr)));
        /* MOV ECX, [ESI + spsr] */
        EmitMovRegBaseDisp32(cursor, kEcx, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, spsr)));
        EmitAndRegImm32(cursor, kEax, 0x1Fu);
        EmitCmpRegImm32(cursor, kEax, ArmMode::kUser);
        /* CMOVE ECX, [ESI + GPRs[Rd]] — 0F 44 mod=10 reg=ECX r/m=ESI disp32. */
        Emit16(cursor, 0x440F);
        EmitModRmReg(cursor, 2, kStateReg, kEcx);
        Emit32(cursor,
            static_cast<uint32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4));
        EmitCmpRegImm32(cursor, kEax, ArmMode::kSystem);
        Emit16(cursor, 0x440F);
        EmitModRmReg(cursor, 2, kStateReg, kEcx);
        Emit32(cursor,
            static_cast<uint32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4));
        store_gpr(d->rd, kEcx);
        break;
    }

    case 3: { /* MSR SPSR, Rm — same user/system fallthrough as MRS SPSR. */
        EmitMovRegBaseDisp32(cursor, kEax, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, cpsr)));
        load_gpr(kEcx, d->rm);
        EmitAndRegImm32(cursor, kEax, 0x1Fu);
        EmitCmpRegImm32(cursor, kEax, ArmMode::kUser);
        Emit16(cursor, 0x440F);
        EmitModRmReg(cursor, 2, kStateReg, kEcx);
        Emit32(cursor, static_cast<uint32_t>(offsetof(ArmCpuState, spsr)));
        EmitCmpRegImm32(cursor, kEax, ArmMode::kSystem);
        Emit16(cursor, 0x440F);
        EmitModRmReg(cursor, 2, kStateReg, kEcx);
        Emit32(cursor, static_cast<uint32_t>(offsetof(ArmCpuState, spsr)));
        EmitMovBaseDisp32Reg(cursor, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, spsr)), kEcx);
        break;
    }

    default:
        LOG(Caution, "PlaceMRSorMSR: unhandled op1=%u\n", d->op1);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        break;
    }
    return cursor;
}
