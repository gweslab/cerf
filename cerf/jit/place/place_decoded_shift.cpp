#include <cstddef>

#include "../../core/log.h"
#include "../arm_jit.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* PlaceDecodedShift(uint8_t*           cursor,
                           const DecodedInsn* d,
                           BlockContext*      ctx,
                           uint8_t            result_reg,
                           bool               needs_shifter_carry_out) {
    using namespace x86;

    /* Operand2 = 4-bit Rm + 8-bit shift specifier. */
    const uint32_t rm        = d->operand2 & 0xFu;
    const uint32_t shift     = d->operand2 >> 4;
    const uint32_t shift_typ = (d->operand2 >> 5) & 3u;
    bool     by_register     = (shift & 1u) != 0u;
    uint32_t shift_amount    = 0;

    if (by_register) {
        const uint32_t rs = shift >> 4;
        if (rs == ArmGpr::kR15) {
            const uint32_t ip = d->guest_address +
                (ctx->jit->CpuState()->cpsr.bits.thumb_mode ? 4u : 8u);
            /* MOV CL, byte ip — B0+CL imm8. */
            Emit8(cursor, 0xB0 + kCl); Emit8(cursor, static_cast<uint8_t>(ip));
        } else {
            /* MOV CL, byte ptr [ESI + offsetof(gprs[rs])]. */
            EmitMovByteRegBaseDisp32(cursor, kCl, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + rs * 4));
        }
    } else {
        shift_amount = shift >> 3;
    }

    /* Load Rm into result_reg. */
    if (rm == ArmGpr::kR15) {
        const uint32_t ip = d->guest_address +
            ((shift & 1u) ? (ctx->jit->CpuState()->cpsr.bits.thumb_mode ? 8u : 12u)
                          : (ctx->jit->CpuState()->cpsr.bits.thumb_mode ? 4u : 8u));
        EmitMovRegImm32(cursor, result_reg, ip);
    } else {
        EmitMovRegBaseDisp32(cursor, result_reg, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, gprs) + rm * 4));
    }

    /* Helper: emit "shift_op result_reg, imm8" using opcode 0xC1.
       op_ext is the /digit (4=SHL, 5=SHR, 7=SAR, 1=ROR, 3=RCR). */
    auto emit_shift_imm = [&](uint8_t op_ext, uint8_t amount) {
        Emit8(cursor, 0xC1);
        EmitModRmReg(cursor, 3, result_reg, op_ext);
        Emit8(cursor, amount);
    };
    /* Emit "shift_op result_reg, 1" using opcode 0xD1. */
    auto emit_shift_one = [&](uint8_t op_ext) {
        Emit8(cursor, 0xD1);
        EmitModRmReg(cursor, 3, result_reg, op_ext);
    };
    /* Emit "shift_op result_reg, CL" using opcode 0xD3. */
    auto emit_shift_cl = [&](uint8_t op_ext) {
        Emit8(cursor, 0xD3);
        EmitModRmReg(cursor, 3, result_reg, op_ext);
    };

    switch (shift_typ) {
    case 0:  /* LSL */
        if (by_register) {
            /* CMP CL, 0x20 — 80 /7. */
            Emit8(cursor, 0x80); EmitModRmReg(cursor, 3, kCl, 7); Emit8(cursor, 0x20);
            uint8_t* jb_lt32  = EmitJbLabel(cursor);
            uint8_t* jz_eq32  = EmitJzLabel(cursor);
            /* Shift > 32: XOR result, result. */
            EmitXorRegReg(cursor, result_reg, result_reg);
            uint8_t* jmp_done1 = EmitJmpLabel(cursor);

            FixupLabel(jz_eq32, cursor);
            emit_shift_imm(4, 31);
            emit_shift_one(4);
            uint8_t* jmp_done2 = EmitJmpLabel(cursor);

            FixupLabel(jb_lt32, cursor);
            if (needs_shifter_carry_out) {
                EmitBtBaseDisp32Imm(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, x86_flags)), 0);
            }
            emit_shift_cl(4);
            FixupLabel(jmp_done1, cursor);
            FixupLabel(jmp_done2, cursor);
            if (needs_shifter_carry_out) {
                EmitSetcReg8(cursor, kCl);
            }
        } else {
            if (shift_amount == 1) {
                emit_shift_one(4);
            } else if (shift_amount == 0) {
                /* No shift. */
            } else if ((shift_amount % 32u) == 0u) {
                emit_shift_imm(4, 16);
                emit_shift_imm(4, static_cast<uint8_t>(shift_amount - 16));
            } else {
                emit_shift_imm(4, static_cast<uint8_t>(shift_amount));
            }
            if (needs_shifter_carry_out) {
                if (shift_amount == 0) {
                    EmitMovByteRegBaseDisp32(cursor, kCl, kStateReg,
                        static_cast<int32_t>(offsetof(ArmCpuState, x86_flags)));
                    Emit8(cursor, 0x80); EmitModRmReg(cursor, 3, kCl, 4); Emit8(cursor, 1);
                } else {
                    EmitSetcReg8(cursor, kCl);
                }
            }
        }
        break;

    case 1:  /* LSR */
        if (by_register) {
            Emit8(cursor, 0x80); EmitModRmReg(cursor, 3, kCl, 7); Emit8(cursor, 0x20);
            uint8_t* jb_lt32 = EmitJbLabel(cursor);
            uint8_t* jz_eq32 = EmitJzLabel(cursor);
            EmitXorRegReg(cursor, result_reg, result_reg);
            uint8_t* jmp_done1 = EmitJmpLabel(cursor);

            FixupLabel(jz_eq32, cursor);
            emit_shift_imm(5, 31);
            emit_shift_one(5);
            uint8_t* jmp_done2 = EmitJmpLabel(cursor);

            FixupLabel(jb_lt32, cursor);
            if (needs_shifter_carry_out) {
                EmitBtBaseDisp32Imm(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, x86_flags)), 0);
            }
            emit_shift_cl(5);
            FixupLabel(jmp_done1, cursor);
            FixupLabel(jmp_done2, cursor);
        } else {
            if (shift_amount == 0) shift_amount = 32;
            if (shift_amount == 1) {
                emit_shift_one(5);
            } else if ((shift_amount % 32u) == 0u) {
                emit_shift_imm(5, 16);
                emit_shift_imm(5, static_cast<uint8_t>(shift_amount - 16));
            } else {
                emit_shift_imm(5, static_cast<uint8_t>(shift_amount));
            }
        }
        if (needs_shifter_carry_out) {
            EmitSetcReg8(cursor, kCl);
        }
        break;

    case 2:  /* ASR */
        if (by_register) {
            Emit8(cursor, 0x80); EmitModRmReg(cursor, 3, kCl, 7); Emit8(cursor, 0x20);
            uint8_t* jb_lt32 = EmitJbLabel(cursor);
            emit_shift_imm(7, 31);
            emit_shift_one(7);
            uint8_t* jmp_done = EmitJmpLabel(cursor);

            FixupLabel(jb_lt32, cursor);
            if (needs_shifter_carry_out) {
                EmitBtBaseDisp32Imm(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, x86_flags)), 0);
            }
            emit_shift_cl(7);
            FixupLabel(jmp_done, cursor);
        } else {
            if (shift_amount == 0) shift_amount = 32;
            if (shift_amount == 1) {
                emit_shift_one(7);
            } else if ((shift_amount % 32u) == 0u) {
                emit_shift_imm(7, 16);
                emit_shift_imm(7, static_cast<uint8_t>(shift_amount - 16));
            } else {
                emit_shift_imm(7, static_cast<uint8_t>(shift_amount));
            }
        }
        if (needs_shifter_carry_out) {
            EmitSetcReg8(cursor, kCl);
        }
        break;

    case 3:  /* ROR */
        if (by_register) {
            /* TEST CL, CL — 84 ModRM(3, CL, CL). */
            Emit8(cursor, 0x84); EmitModRmReg(cursor, 3, kCl, kCl);
            uint8_t* jz_no_shift = EmitJzLabel(cursor);
            /* AND CL, 0x1F — 80 /4. */
            Emit8(cursor, 0x80); EmitModRmReg(cursor, 3, kCl, 4); Emit8(cursor, 0x1F);
            uint8_t* jz_by_zero = EmitJzLabel(cursor);
            /* ROR result, CL — D3 /1. */
            emit_shift_cl(1);
            uint8_t* jmp_done1 = EmitJmpLabel(cursor);

            FixupLabel(jz_no_shift, cursor);
            if (needs_shifter_carry_out) {
                EmitBtBaseDisp32Imm(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, x86_flags)), 0);
            }
            uint8_t* jmp_done2 = EmitJmpLabel(cursor);

            FixupLabel(jz_by_zero, cursor);
            if (needs_shifter_carry_out) {
                EmitMovRegReg(cursor, kEcx, result_reg);
                /* SHL ECX, 1 — D1 /4. */
                Emit8(cursor, 0xD1); EmitModRmReg(cursor, 3, kEcx, 4);
            }
            FixupLabel(jmp_done1, cursor);
            FixupLabel(jmp_done2, cursor);
        } else {
            if (shift_amount == 0) {
                /* ROR #0 = RRX (rotate-right with extend through CF). */
                EmitBtBaseDisp32Imm(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, x86_flags)), 0);
                /* RCR result, 1 — D1 /3. */
                Emit8(cursor, 0xD1); EmitModRmReg(cursor, 3, result_reg, 3);
            } else if (shift_amount == 1) {
                emit_shift_one(1);
            } else if ((shift_amount % 32u) == 0u) {
                emit_shift_imm(1, 16);
                emit_shift_imm(1, static_cast<uint8_t>(shift_amount - 16));
            } else {
                emit_shift_imm(1, static_cast<uint8_t>(shift_amount));
            }
        }
        if (needs_shifter_carry_out) {
            EmitSetcReg8(cursor, kCl);
        }
        break;

    default:
        LOG(Caution, "PlaceDecodedShift: unhandled shift_type %u\n", shift_typ);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        break;
    }
    return cursor;
}
