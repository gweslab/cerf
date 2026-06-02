#include <cstddef>

#include "../../core/log.h"
#include "../arm_cpu.h"
#include "../arm_jit.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* PlaceDataProcessing(uint8_t*      cursor,
                             DecodedInsn*  d,
                             BlockContext* ctx) {
    using namespace x86;

    constexpr uint8_t imm_reg = kEdx;
    bool needs_sco = false;

    /* Helper for "load Cpu.GPRs[Rn] or R15-immediate into EAX". */
    auto load_rn_to_eax = [&]() {
        if (d->rn == ArmGpr::kR15) {
            EmitMovRegImm32(cursor, kEax,
                d->guest_address +
                (ctx->jit->CpuState()->cpsr.bits.thumb_mode ? 4u : 8u));
        } else {
            EmitMovRegBaseDisp32(cursor, kEax, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4));
        }
    };
    auto store_eax_to_rd = [&]() {
        EmitMovBaseDisp32Reg(cursor, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4),
            kEax);
    };
    auto store_imm_reg_to_rd = [&]() {
        EmitMovBaseDisp32Reg(cursor, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4),
            imm_reg);
    };
    auto bt_x86_flags_cf = [&]() {
        EmitBtBaseDisp32Imm(cursor, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, x86_flags)), 0);
    };

    switch (d->opcode) {
    case 0:  /* AND Rd = Rn AND op2 */
        if (d->s && (d->flags_set & kFlagC)) needs_sco = true;
        if (!d->i) cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, needs_sco);
        cursor = PlaceBasicTwoAddrWithResult(cursor, 0x21, 0x81, 4, d, ctx, imm_reg);
        if (needs_sco) cursor = PlaceShifterCarryOut(cursor, d, ctx);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/true);
        break;

    case 1:  /* EOR */
        if (d->s && (d->flags_set & kFlagC)) needs_sco = true;
        if (!d->i) cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, needs_sco);
        cursor = PlaceBasicTwoAddrWithResult(cursor, 0x31, 0x81, 6, d, ctx, imm_reg);
        if (needs_sco) cursor = PlaceShifterCarryOut(cursor, d, ctx);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/true);
        break;

    case 2:  /* SUB */
        if (!d->i) cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, /*needs_sco=*/false);
        cursor = PlaceBasicTwoAddrWithResult(cursor, 0x29, 0x81, 5, d, ctx, imm_reg);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/false);
        break;

    case 3:  /* RSB Rd = imm - Rn */
        if (d->i) {
            if (d->reserved3) {
                EmitMovRegImm32(cursor, imm_reg, d->reserved3);
            } else {
                EmitXorRegReg(cursor, imm_reg, imm_reg);
            }
        } else {
            cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, /*needs_sco=*/false);
        }
        load_rn_to_eax();
        /* SUB imm_reg, EAX  →  imm_reg = imm_reg - Rn. Encoded as 0x29 /r ModRM. */
        Emit8(cursor, 0x29); EmitModRmReg(cursor, 3, imm_reg, kEax);
        store_imm_reg_to_rd();
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/false);
        break;

    case 4:  /* ADD */
        if (!d->i) cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, /*needs_sco=*/false);
        cursor = PlaceBasicTwoAddrWithResult(cursor, 0x01, 0x81, 0, d, ctx, imm_reg);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/true);
        break;

    case 5:  /* ADC */
        if (!d->i) cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, /*needs_sco=*/false);
        bt_x86_flags_cf();  /* set host CF from x86_flags */
        cursor = PlaceBasicTwoAddrWithResult(cursor, 0x11, 0x81, 2, d, ctx, imm_reg);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/true);
        break;

    case 6:  /* SBC Rd = Rn - imm - !C */
        if (d->i) {
            if (d->reserved3) EmitMovRegImm32(cursor, imm_reg, d->reserved3);
            else EmitXorRegReg(cursor, imm_reg, imm_reg);
        } else {
            cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, /*needs_sco=*/false);
        }
        bt_x86_flags_cf();
        EmitCmc(cursor);  /* invert host CF */
        load_rn_to_eax();
        /* SBB EAX, imm_reg  → EAX = EAX - imm_reg - CF. Encoded as 0x1B /r. */
        Emit8(cursor, 0x1B); EmitModRmReg(cursor, 3, imm_reg, kEax);
        store_eax_to_rd();
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/false);
        break;

    case 7:  /* RSC Rd = imm - Rn - !C */
        if (d->i) {
            if (d->reserved3) EmitMovRegImm32(cursor, imm_reg, d->reserved3);
            else EmitXorRegReg(cursor, imm_reg, imm_reg);
        } else {
            cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, /*needs_sco=*/false);
        }
        bt_x86_flags_cf();
        EmitCmc(cursor);
        load_rn_to_eax();
        /* SBB imm_reg, EAX  → imm_reg = imm_reg - EAX - CF. */
        Emit8(cursor, 0x1B); EmitModRmReg(cursor, 3, kEax, imm_reg);
        store_imm_reg_to_rd();
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/false);
        break;

    case 8:  /* TST */
        if (d->flags_set & kFlagC) needs_sco = true;
        if (!d->i) cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, needs_sco);
        cursor = PlaceBasicTwoAddrNoResult(cursor, 0x85, 0xF7, 0, d, ctx, imm_reg, /*fSide=*/false);
        if (needs_sco) cursor = PlaceShifterCarryOut(cursor, d, ctx);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/true);
        break;

    case 9:  /* TEQ */
        if (d->flags_set & kFlagC) needs_sco = true;
        if (!d->i) cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, needs_sco);
        cursor = PlaceBasicTwoAddrNoResult(cursor, 0x31, 0x81, 6, d, ctx, imm_reg, /*fSide=*/true);
        if (needs_sco) cursor = PlaceShifterCarryOut(cursor, d, ctx);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/true);
        break;

    case 10:  /* CMP */
        if (!d->i) cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, /*needs_sco=*/false);
        cursor = PlaceBasicTwoAddrNoResult(cursor, 0x39, 0x81, 7, d, ctx, imm_reg, /*fSide=*/false);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/false);
        break;

    case 11:  /* CMN */
        if (!d->i) cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, /*needs_sco=*/false);
        cursor = PlaceBasicTwoAddrNoResult(cursor, 0x01, 0x81, 0, d, ctx, imm_reg, /*fSide=*/true);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/true);
        break;

    case 12:  /* ORR */
        if (d->s && (d->flags_set & kFlagC)) needs_sco = true;
        if (!d->i) cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, needs_sco);
        cursor = PlaceBasicTwoAddrWithResult(cursor, 0x09, 0x81, 1, d, ctx, imm_reg);
        if (needs_sco) cursor = PlaceShifterCarryOut(cursor, d, ctx);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/true);
        break;

    case 13:  /* MOV */
        if (d->s && (d->flags_set & kFlagC)) needs_sco = true;
        if (d->i) {
            const uint32_t imm = d->reserved3;
            if (d->s) {
                EmitMovRegImm32(cursor, kEax, imm);
                store_eax_to_rd();
                EmitTestRegReg(cursor, kEax, kEax);
            } else {
                /* MOV [ESI + offset], imm32 — C7 /0 mod=10. */
                EmitMovBaseDisp32Imm32(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4),
                    imm);
            }
        } else {
            cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, needs_sco);
            if (d->s && d->rd == d->operand2) {
                /* MOVES Rd, Rd — store optimized out (NetCF NULL check). */
            } else {
                store_imm_reg_to_rd();
            }
            if (d->s && d->rd != ArmGpr::kR15) {
                /* TEST imm_reg, imm_reg — set ZF/SF, clear OF/CF. */
                EmitTestRegReg(cursor, imm_reg, imm_reg);
            }
        }
        if (needs_sco) cursor = PlaceShifterCarryOut(cursor, d, ctx);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/true);
        break;

    case 14:  /* BIC Rd = Rn AND NOT op2 */
        if (d->s && (d->flags_set & kFlagC)) needs_sco = true;
        if (d->i) {
            d->reserved3 = ~d->reserved3;
        } else {
            cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, needs_sco);
            /* NOT imm_reg — F7 /2. */
            Emit8(cursor, 0xF7); EmitModRmReg(cursor, 3, imm_reg, 2);
        }
        cursor = PlaceBasicTwoAddrWithResult(cursor, 0x21, 0x81, 4, d, ctx, imm_reg);
        if (d->i) d->reserved3 = ~d->reserved3;
        if (needs_sco) cursor = PlaceShifterCarryOut(cursor, d, ctx);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/true);
        break;

    case 15:  /* MVN Rd = NOT op2 */
        if (d->s && (d->flags_set & kFlagC)) needs_sco = true;
        if (d->i) {
            const uint32_t imm = ~d->reserved3;
            if (d->s && d->rd != ArmGpr::kR15) {
                EmitMovRegImm32(cursor, kEax, imm);
                store_eax_to_rd();
                EmitTestRegReg(cursor, kEax, kEax);
            } else {
                EmitMovBaseDisp32Imm32(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4),
                    imm);
            }
        } else {
            cursor = PlaceDecodedShift(cursor, d, ctx, imm_reg, needs_sco);
            Emit8(cursor, 0xF7); EmitModRmReg(cursor, 3, imm_reg, 2);  /* NOT */
            if (d->s && d->rd != ArmGpr::kR15) {
                EmitTestRegReg(cursor, imm_reg, imm_reg);
            }
            store_imm_reg_to_rd();
        }
        if (needs_sco) cursor = PlaceShifterCarryOut(cursor, d, ctx);
        cursor = PlaceUpdateX86Flags(cursor, d, ctx, /*fAdd=*/true);
        break;

    default:
        LOG(Caution, "PlaceDataProcessing: unhandled opcode %u\n", d->opcode);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        break;
    }

    if (d->r15_modified) {
        if (d->is_exception_return) {
            /* PUSH [ESI + offsetof(spsr)] */
            EmitPushBaseDisp32(cursor, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, spsr)));
            EmitPush32(cursor,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ctx->jit->Cpu())));
            EmitCall(cursor,
                reinterpret_cast<void*>(&ArmCpu::UpdateCpsrWithFlagsHelper));
            EmitAddRegImm32(cursor, kEsp, 8);

            /* MOV EAX, [ESI + offsetof(gprs[15])] — re-load PC value
               the opcode case stored before CPSR restore. */
            EmitMovRegBaseDisp32(cursor, kEax, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15u * 4u));
            /* MOV EDX, ~1; MOV ECX, ~3; TEST [ESI+cpsr], 0x20;
               CMOVNZ ECX, EDX; AND EAX, ECX. Pick the PC mask
               based on CPSR.T. */
            EmitMovRegImm32(cursor, kEdx, ~uint32_t{1});
            EmitMovRegImm32(cursor, kEcx, ~uint32_t{3});
            /* TEST DWORD PTR [ESI + offsetof(cpsr)], 0x20  —
               F7 /0 mod=10 r/m=ESI(6) reg=0 disp32 imm32. */
            Emit8(cursor, 0xF7);
            EmitModRmReg(cursor, 2, kStateReg, 0);
            Emit32(cursor,
                static_cast<uint32_t>(offsetof(ArmCpuState, cpsr)));
            Emit32(cursor, 0x20u);
            /* CMOVNZ ECX, EDX — 0F 45 mod=11 r/m=EDX reg=ECX. */
            Emit8(cursor, 0x0F); Emit8(cursor, 0x45);
            EmitModRmReg(cursor, 3, kEdx, kEcx);
            /* AND EAX, ECX — 23 mod=11 r/m=ECX reg=EAX. */
            Emit8(cursor, 0x23);
            EmitModRmReg(cursor, 3, kEcx, kEax);
            EmitMovBaseDisp32Reg(cursor, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15u * 4u),
                kEax);
        } else if (!ctx->jit->CpuState()->cpsr.bits.thumb_mode) {
            /* ARM-state data-proc Rd=PC without S: interworking branch
               per ddi0406c §A2.3.1 line 2082. */
            EmitMovRegBaseDisp32(cursor, kEax, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15u * 4u));
            cursor = EmitArmInterworkingMaskEax(cursor);
            EmitMovBaseDisp32Reg(cursor, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15u * 4u),
                kEax);
        } else {
            /* Thumb-state data-proc Rd=PC (Thumb hi-ops synthesized into
               ARM data-proc): halfword-align per ddi0406c §A2.3.1
               lines 2065-2066. No ISA switch. */
            EmitMovRegBaseDisp32(cursor, kEax, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15u * 4u));
            EmitAndRegImm32(cursor, kEax, 0xFFFFFFFEu);
            EmitMovBaseDisp32Reg(cursor, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15u * 4u),
                kEax);
        }
        if (d->opcode == 13 && d->rm == ArmGpr::kR14 && !d->i && !d->s) {
            /* MOV R15, R14 — plain return idiom (shadow-stack fast path).
               MOVS R15, R14 (S=1) is an exception return — falls through
               to PlaceR15ModifiedHelper with the CPSR restore from above. */
            EmitJmp32(cursor, ctx->pop_shadow_stack_helper_target);
        } else {
            cursor = PlaceR15ModifiedHelper(cursor, d, ctx);
        }
    }
    return cursor;
}
