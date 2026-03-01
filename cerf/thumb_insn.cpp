/* Thumb mode instruction implementations */
#include "arm_cpu.h"

void ArmCpu::ExecuteThumb(uint16_t insn) {
    uint16_t op = (insn >> 8) & 0xFF;

    /* Format 1: Move shifted register */
    if ((insn >> 13) == 0) {
        ThumbShiftImm(insn);
        return;
    }

    /* Format 2: Add/subtract */
    if ((insn >> 11) == 3) {
        ThumbAddSub(insn);
        return;
    }

    /* Format 3: Move/compare/add/subtract immediate */
    if ((insn >> 13) == 1) {
        ThumbMovCmpAddSub(insn);
        return;
    }

    /* Format 4: ALU operations */
    if ((insn >> 10) == 0x10) {
        ThumbALU(insn);
        return;
    }

    /* Format 5: Hi register operations / BX */
    if ((insn >> 10) == 0x11) {
        ThumbHiRegBX(insn);
        return;
    }

    /* Format 6: PC-relative load */
    if ((insn >> 11) == 9) {
        ThumbPCRelLoad(insn);
        return;
    }

    /* Format 7: Load/store with register offset */
    if ((insn >> 12) == 5 && !((insn >> 9) & 1)) {
        ThumbLoadStoreReg(insn);
        return;
    }

    /* Format 8: Load/store sign-extended byte/halfword */
    if ((insn >> 12) == 5 && ((insn >> 9) & 1)) {
        ThumbLoadStoreSBH(insn);
        return;
    }

    /* Format 9: Load/store with immediate offset */
    if ((insn >> 13) == 3) {
        ThumbLoadStoreImm(insn);
        return;
    }

    /* Format 10: Load/store halfword */
    if ((insn >> 12) == 8) {
        ThumbLoadStoreHalf(insn);
        return;
    }

    /* Format 11: SP-relative load/store */
    if ((insn >> 12) == 9) {
        ThumbSPRelLoadStore(insn);
        return;
    }

    /* Format 12: Load address */
    if ((insn >> 12) == 0xA) {
        ThumbLoadAddr(insn);
        return;
    }

    /* Format 13: Add offset to SP */
    if ((insn >> 8) == 0xB0) {
        ThumbAdjustSP(insn);
        return;
    }

    /* Format 14: Push/pop registers */
    if ((insn >> 12) == 0xB && ((insn >> 9) & 3) == 2) {
        ThumbPushPop(insn);
        return;
    }

    /* Format 15: Multiple load/store */
    if ((insn >> 12) == 0xC) {
        ThumbMultiLoadStore(insn);
        return;
    }

    /* Format 16: Conditional branch */
    if ((insn >> 12) == 0xD && ((insn >> 8) & 0xF) < 0xE) {
        ThumbCondBranch(insn);
        return;
    }

    /* Format 17: SWI */
    if ((insn >> 8) == 0xDF) {
        ThumbSWI(insn);
        return;
    }

    /* Format 18: Unconditional branch */
    if ((insn >> 11) == 0x1C) {
        ThumbUncondBranch(insn);
        return;
    }

    /* Format 19: Long branch with link */
    if ((insn >> 11) >= 0x1E) {
        ThumbLongBranch(insn);
        return;
    }

    fprintf(stderr, "[THUMB] Unhandled instruction: 0x%04X at PC=0x%08X\n", insn, r[REG_PC] - 2);
    halted = true;
    halt_code = 1;
}

void ArmCpu::ThumbShiftImm(uint16_t insn) {
    uint32_t op = (insn >> 11) & 3;
    uint32_t offset = (insn >> 6) & 0x1F;
    uint32_t rs = (insn >> 3) & 7;
    uint32_t rd = insn & 7;
    bool carry;

    uint32_t result = BarrelShift(r[rs], op, offset, carry, false);
    r[rd] = result;
    SetNZ(result);
    SetC(carry);
}

void ArmCpu::ThumbAddSub(uint16_t insn) {
    bool I = (insn >> 10) & 1;
    bool op = (insn >> 9) & 1;
    uint32_t rn_or_imm = (insn >> 6) & 7;
    uint32_t rs = (insn >> 3) & 7;
    uint32_t rd = insn & 7;

    uint32_t operand = I ? rn_or_imm : r[rn_or_imm];
    uint32_t result;

    if (op) { /* SUB */
        result = r[rs] - operand;
        SetC(r[rs] >= operand);
        SetV(((r[rs] ^ operand) & (r[rs] ^ result)) >> 31);
    } else { /* ADD */
        result = r[rs] + operand;
        SetC(result < r[rs]);
        SetV(((r[rs] ^ ~operand) & (r[rs] ^ result)) >> 31);
    }
    r[rd] = result;
    SetNZ(result);
}

void ArmCpu::ThumbMovCmpAddSub(uint16_t insn) {
    uint32_t op = (insn >> 11) & 3;
    uint32_t rd = (insn >> 8) & 7;
    uint32_t imm = insn & 0xFF;

    uint32_t result;
    switch (op) {
    case 0: /* MOV */
        r[rd] = imm;
        SetNZ(imm);
        break;
    case 1: /* CMP */
        result = r[rd] - imm;
        SetNZ(result);
        SetC(r[rd] >= imm);
        SetV(((r[rd] ^ imm) & (r[rd] ^ result)) >> 31);
        break;
    case 2: /* ADD */
        result = r[rd] + imm;
        SetC(result < r[rd]);
        SetV(((r[rd] ^ ~imm) & (r[rd] ^ result)) >> 31);
        r[rd] = result;
        SetNZ(result);
        break;
    case 3: /* SUB */
        result = r[rd] - imm;
        SetC(r[rd] >= imm);
        SetV(((r[rd] ^ imm) & (r[rd] ^ result)) >> 31);
        r[rd] = result;
        SetNZ(result);
        break;
    }
}

void ArmCpu::ThumbALU(uint16_t insn) {
    uint32_t op = (insn >> 6) & 0xF;
    uint32_t rs = (insn >> 3) & 7;
    uint32_t rd = insn & 7;

    uint32_t result;
    bool carry;

    switch (op) {
    case 0x0: /* AND */
        r[rd] &= r[rs];
        SetNZ(r[rd]);
        break;
    case 0x1: /* EOR */
        r[rd] ^= r[rs];
        SetNZ(r[rd]);
        break;
    case 0x2: /* LSL */
        result = BarrelShift(r[rd], 0, r[rs] & 0xFF, carry, true);
        r[rd] = result;
        SetNZ(result);
        if (r[rs] & 0xFF) SetC(carry);
        break;
    case 0x3: /* LSR */
        result = BarrelShift(r[rd], 1, r[rs] & 0xFF, carry, true);
        r[rd] = result;
        SetNZ(result);
        if (r[rs] & 0xFF) SetC(carry);
        break;
    case 0x4: /* ASR */
        result = BarrelShift(r[rd], 2, r[rs] & 0xFF, carry, true);
        r[rd] = result;
        SetNZ(result);
        if (r[rs] & 0xFF) SetC(carry);
        break;
    case 0x5: /* ADC */
        result = r[rd] + r[rs] + (GetC() ? 1 : 0);
        SetC((uint64_t)r[rd] + r[rs] + (GetC() ? 1 : 0) > 0xFFFFFFFF);
        SetV(((r[rd] ^ ~r[rs]) & (r[rd] ^ result)) >> 31);
        r[rd] = result;
        SetNZ(result);
        break;
    case 0x6: /* SBC */
        result = r[rd] - r[rs] - (GetC() ? 0 : 1);
        SetC((uint64_t)r[rd] >= (uint64_t)r[rs] + (GetC() ? 0 : 1));
        SetV(((r[rd] ^ r[rs]) & (r[rd] ^ result)) >> 31);
        r[rd] = result;
        SetNZ(result);
        break;
    case 0x7: /* ROR */
        result = BarrelShift(r[rd], 3, r[rs] & 0xFF, carry, true);
        r[rd] = result;
        SetNZ(result);
        if (r[rs] & 0xFF) SetC(carry);
        break;
    case 0x8: /* TST */
        SetNZ(r[rd] & r[rs]);
        break;
    case 0x9: /* NEG */
        result = 0 - r[rs];
        SetC(r[rs] == 0);
        SetV(((r[rs]) & (result)) >> 31);
        r[rd] = result;
        SetNZ(result);
        break;
    case 0xA: /* CMP */
        result = r[rd] - r[rs];
        SetNZ(result);
        SetC(r[rd] >= r[rs]);
        SetV(((r[rd] ^ r[rs]) & (r[rd] ^ result)) >> 31);
        break;
    case 0xB: /* CMN */
        result = r[rd] + r[rs];
        SetNZ(result);
        SetC(result < r[rd]);
        SetV(((r[rd] ^ ~r[rs]) & (r[rd] ^ result)) >> 31);
        break;
    case 0xC: /* ORR */
        r[rd] |= r[rs];
        SetNZ(r[rd]);
        break;
    case 0xD: /* MUL */
        r[rd] *= r[rs];
        SetNZ(r[rd]);
        break;
    case 0xE: /* BIC */
        r[rd] &= ~r[rs];
        SetNZ(r[rd]);
        break;
    case 0xF: /* MVN */
        r[rd] = ~r[rs];
        SetNZ(r[rd]);
        break;
    }
}

void ArmCpu::ThumbHiRegBX(uint16_t insn) {
    uint32_t op = (insn >> 8) & 3;
    bool h1 = (insn >> 7) & 1;
    bool h2 = (insn >> 6) & 1;
    uint32_t rs = ((h2 ? 8 : 0) | ((insn >> 3) & 7));
    uint32_t rd = ((h1 ? 8 : 0) | (insn & 7));

    uint32_t rs_val = r[rs];
    if (rs == REG_PC) rs_val += 2;

    switch (op) {
    case 0: /* ADD */
        r[rd] += rs_val;
        if (rd == REG_PC) r[REG_PC] &= ~1u;
        break;
    case 1: /* CMP */
    {
        uint32_t result = r[rd] - rs_val;
        SetNZ(result);
        SetC(r[rd] >= rs_val);
        SetV(((r[rd] ^ rs_val) & (r[rd] ^ result)) >> 31);
        break;
    }
    case 2: /* MOV */
        r[rd] = rs_val;
        if (rd == REG_PC) r[REG_PC] &= ~1u;
        break;
    case 3: /* BX */
    {
        uint32_t target = rs_val;
        if (thunk_handler && thunk_handler(target & ~1u, r, *mem)) return;
        if (target & 1) {
            cpsr |= PSR_T;
            r[REG_PC] = target & ~1u;
        } else {
            cpsr &= ~PSR_T;
            r[REG_PC] = target & ~3u;
        }
        break;
    }
    }
}

void ArmCpu::ThumbPCRelLoad(uint16_t insn) {
    uint32_t rd = (insn >> 8) & 7;
    uint32_t offset = (insn & 0xFF) << 2;
    uint32_t addr = (r[REG_PC] & ~3u) + offset + 2;
    r[rd] = mem->Read32(addr);
}

void ArmCpu::ThumbLoadStoreReg(uint16_t insn) {
    uint32_t op = (insn >> 10) & 3;
    uint32_t ro = (insn >> 6) & 7;
    uint32_t rb = (insn >> 3) & 7;
    uint32_t rd = insn & 7;
    uint32_t addr = r[rb] + r[ro];

    switch (op) {
    case 0: /* STR */
        mem->Write32(addr, r[rd]);
        break;
    case 1: /* STRB */
        mem->Write8(addr, (uint8_t)r[rd]);
        break;
    case 2: /* LDR */
        r[rd] = mem->Read32(addr & ~3u);
        break;
    case 3: /* LDRB */
        r[rd] = mem->Read8(addr);
        break;
    }
}

void ArmCpu::ThumbLoadStoreSBH(uint16_t insn) {
    uint32_t op = (insn >> 10) & 3;
    uint32_t ro = (insn >> 6) & 7;
    uint32_t rb = (insn >> 3) & 7;
    uint32_t rd = insn & 7;
    uint32_t addr = r[rb] + r[ro];

    switch (op) {
    case 0: /* STRH */
        mem->Write16(addr, (uint16_t)r[rd]);
        break;
    case 1: /* LDSB */
        r[rd] = (int32_t)(int8_t)mem->Read8(addr);
        break;
    case 2: /* LDRH */
        r[rd] = mem->Read16(addr);
        break;
    case 3: /* LDSH */
        r[rd] = (int32_t)(int16_t)mem->Read16(addr);
        break;
    }
}

void ArmCpu::ThumbLoadStoreImm(uint16_t insn) {
    bool B = (insn >> 12) & 1;
    bool L = (insn >> 11) & 1;
    uint32_t offset = (insn >> 6) & 0x1F;
    uint32_t rb = (insn >> 3) & 7;
    uint32_t rd = insn & 7;

    if (B) {
        uint32_t addr = r[rb] + offset;
        if (L) {
            r[rd] = mem->Read8(addr);
        } else {
            mem->Write8(addr, (uint8_t)r[rd]);
        }
    } else {
        offset <<= 2;
        uint32_t addr = r[rb] + offset;
        if (L) {
            r[rd] = mem->Read32(addr);
        } else {
            mem->Write32(addr, r[rd]);
        }
    }
}

void ArmCpu::ThumbLoadStoreHalf(uint16_t insn) {
    bool L = (insn >> 11) & 1;
    uint32_t offset = ((insn >> 6) & 0x1F) << 1;
    uint32_t rb = (insn >> 3) & 7;
    uint32_t rd = insn & 7;
    uint32_t addr = r[rb] + offset;

    if (L) {
        r[rd] = mem->Read16(addr);
    } else {
        mem->Write16(addr, (uint16_t)r[rd]);
    }
}

void ArmCpu::ThumbSPRelLoadStore(uint16_t insn) {
    bool L = (insn >> 11) & 1;
    uint32_t rd = (insn >> 8) & 7;
    uint32_t offset = (insn & 0xFF) << 2;
    uint32_t addr = r[REG_SP] + offset;

    if (L) {
        r[rd] = mem->Read32(addr);
    } else {
        mem->Write32(addr, r[rd]);
    }
}

void ArmCpu::ThumbLoadAddr(uint16_t insn) {
    bool sp = (insn >> 11) & 1;
    uint32_t rd = (insn >> 8) & 7;
    uint32_t offset = (insn & 0xFF) << 2;

    if (sp) {
        r[rd] = r[REG_SP] + offset;
    } else {
        r[rd] = (r[REG_PC] & ~3u) + offset + 2;
    }
}

void ArmCpu::ThumbAdjustSP(uint16_t insn) {
    uint32_t offset = (insn & 0x7F) << 2;
    if (insn & 0x80) {
        r[REG_SP] -= offset;
    } else {
        r[REG_SP] += offset;
    }
}

void ArmCpu::ThumbPushPop(uint16_t insn) {
    bool L = (insn >> 11) & 1;  /* Load (POP) / Store (PUSH) */
    bool R = (insn >> 8) & 1;   /* PC/LR */
    uint8_t reg_list = insn & 0xFF;

    if (L) {
        /* POP */
        for (int i = 0; i < 8; i++) {
            if (reg_list & (1 << i)) {
                r[i] = mem->Read32(r[REG_SP]);
                r[REG_SP] += 4;
            }
        }
        if (R) {
            uint32_t val = mem->Read32(r[REG_SP]);
            r[REG_SP] += 4;

            /* Check for thunk */
            if (thunk_handler && thunk_handler(val & ~1u, r, *mem)) return;

            if (val & 1) {
                cpsr |= PSR_T;
                r[REG_PC] = val & ~1u;
            } else {
                cpsr &= ~PSR_T;
                r[REG_PC] = val & ~3u;
            }
        }
    } else {
        /* PUSH */
        if (R) {
            r[REG_SP] -= 4;
            mem->Write32(r[REG_SP], r[REG_LR]);
        }
        for (int i = 7; i >= 0; i--) {
            if (reg_list & (1 << i)) {
                r[REG_SP] -= 4;
                mem->Write32(r[REG_SP], r[i]);
            }
        }
    }
}

void ArmCpu::ThumbMultiLoadStore(uint16_t insn) {
    bool L = (insn >> 11) & 1;
    uint32_t rb = (insn >> 8) & 7;
    uint8_t reg_list = insn & 0xFF;
    uint32_t addr = r[rb];

    for (int i = 0; i < 8; i++) {
        if (!(reg_list & (1 << i))) continue;
        if (L) {
            r[i] = mem->Read32(addr);
        } else {
            mem->Write32(addr, r[i]);
        }
        addr += 4;
    }
    /* Write-back (always for STMIA, for LDMIA only if rb not in list) */
    if (!L || !(reg_list & (1 << rb))) {
        r[rb] = addr;
    }
}

void ArmCpu::ThumbCondBranch(uint16_t insn) {
    uint32_t cond = (insn >> 8) & 0xF;
    if (!CheckCondition(cond)) return;

    int32_t offset = (int32_t)(int8_t)(insn & 0xFF);
    offset <<= 1;
    r[REG_PC] = r[REG_PC] + offset + 2;
}

void ArmCpu::ThumbSWI(uint16_t insn) {
    uint32_t swi_num = insn & 0xFF;
    fprintf(stderr, "[THUMB] SWI #0x%X at PC=0x%08X\n", swi_num, r[REG_PC] - 2);

    if (thunk_handler) {
        uint32_t swi_addr = 0xFFFF0000 | swi_num;
        if (thunk_handler(swi_addr, r, *mem)) return;
    }

    halted = true;
    halt_code = 2;
}

void ArmCpu::ThumbUncondBranch(uint16_t insn) {
    int32_t offset = insn & 0x7FF;
    if (offset & 0x400) offset |= 0xFFFFF800; /* Sign extend */
    offset <<= 1;

    uint32_t target = r[REG_PC] + offset + 2;
    if (thunk_handler && thunk_handler(target, r, *mem)) return;
    r[REG_PC] = target;
}

void ArmCpu::ThumbLongBranch(uint16_t insn) {
    uint32_t H = (insn >> 11) & 3;

    if (H == 2) {
        /* First instruction: LR = PC + (offset << 12) */
        int32_t offset = insn & 0x7FF;
        if (offset & 0x400) offset |= 0xFFFFF800;
        r[REG_LR] = r[REG_PC] + 2 + (offset << 12);
    } else if (H == 3) {
        /* Second instruction: BL */
        uint32_t offset = (insn & 0x7FF) << 1;
        uint32_t target = r[REG_LR] + offset;
        r[REG_LR] = (r[REG_PC]) | 1; /* Return address with Thumb bit */

        if (thunk_handler && thunk_handler(target & ~1u, r, *mem)) return;

        r[REG_PC] = target & ~1u;
    } else if (H == 1) {
        /* BLX - switch to ARM mode */
        uint32_t offset = (insn & 0x7FF) << 1;
        uint32_t target = (r[REG_LR] + offset) & ~3u;
        r[REG_LR] = (r[REG_PC]) | 1;

        if (thunk_handler && thunk_handler(target, r, *mem)) return;

        cpsr &= ~PSR_T;
        r[REG_PC] = target;
    }
}
