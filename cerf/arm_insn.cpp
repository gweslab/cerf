/* ARM mode instruction implementations */
#include "arm_cpu.h"
#include <cstdlib>

void ArmCpu::ExecuteArm(uint32_t insn) {
    uint32_t cond = (insn >> 28) & 0xF;

    if (!CheckCondition(cond)) return;

    uint32_t op = (insn >> 20) & 0xFF;
    uint32_t bits7_4 = (insn >> 4) & 0xF;

    /* Decode ARM instruction classes */

    /* Branch and Exchange (BX, BLX) */
    if ((insn & 0x0FFFFFF0) == 0x012FFF10) {
        ArmBranchExchange(insn);
        return;
    }

    /* BLX register (ARMv5) */
    if ((insn & 0x0FFFFFF0) == 0x012FFF30) {
        uint32_t rm = insn & 0xF;
        uint32_t target = r[rm];
        r[REG_LR] = r[REG_PC]; /* PC already advanced by 4 */

        /* Check for thunk */
        if (thunk_handler && thunk_handler(target & ~1u, r, *mem)) {
            return;
        }

        if (target & 1) {
            cpsr |= PSR_T;
            r[REG_PC] = target & ~1u;
        } else {
            r[REG_PC] = target & ~3u;
        }
        return;
    }

    /* CLZ (ARMv5) */
    if ((insn & 0x0FFF0FF0) == 0x016F0F10) {
        ArmCLZ(insn);
        return;
    }

    /* Multiply */
    if ((insn & 0x0FC000F0) == 0x00000090) {
        ArmMultiply(insn);
        return;
    }

    /* Multiply Long */
    if ((insn & 0x0F8000F0) == 0x00800090) {
        ArmMultiplyLong(insn);
        return;
    }

    /* Swap */
    if ((insn & 0x0FB00FF0) == 0x01000090) {
        ArmSwap(insn);
        return;
    }

    /* Halfword / signed byte transfers */
    if (((insn & 0x0E000090) == 0x00000090) && ((bits7_4 & 0x9) == 0x9) && (bits7_4 != 0x9)) {
        ArmHalfwordTransfer(insn);
        return;
    }

    /* MRS */
    if ((insn & 0x0FBF0FFF) == 0x010F0000) {
        ArmMRS(insn);
        return;
    }

    /* MSR (register) */
    if ((insn & 0x0FB0FFF0) == 0x0120F000) {
        ArmMSR(insn);
        return;
    }

    /* MSR (immediate) */
    if ((insn & 0x0FB0F000) == 0x0320F000) {
        ArmMSR(insn);
        return;
    }

    /* Data processing */
    if ((insn & 0x0C000000) == 0x00000000) {
        ArmDataProcessing(insn);
        return;
    }

    /* Single data transfer (LDR/STR) */
    if ((insn & 0x0C000000) == 0x04000000) {
        ArmSingleDataTransfer(insn);
        return;
    }

    /* Block data transfer (LDM/STM) */
    if ((insn & 0x0E000000) == 0x08000000) {
        ArmBlockDataTransfer(insn);
        return;
    }

    /* Branch / Branch with Link */
    if ((insn & 0x0E000000) == 0x0A000000) {
        ArmBranch(insn);
        return;
    }

    /* Software Interrupt */
    if ((insn & 0x0F000000) == 0x0F000000) {
        ArmSoftwareInterrupt(insn);
        return;
    }

    /* Coprocessor / undefined */
    fprintf(stderr, "[ARM] Unhandled instruction: 0x%08X at PC=0x%08X\n", insn, r[REG_PC] - 4);
    halted = true;
    halt_code = 1;
}

void ArmCpu::ArmDataProcessing(uint32_t insn) {
    uint32_t opcode = (insn >> 21) & 0xF;
    bool S = (insn >> 20) & 1;
    uint32_t rn = (insn >> 16) & 0xF;
    uint32_t rd = (insn >> 12) & 0xF;
    bool I = (insn >> 25) & 1;

    uint32_t op2;
    bool shifter_carry = GetC();

    if (I) {
        /* Immediate operand */
        uint32_t imm = insn & 0xFF;
        uint32_t rot = ((insn >> 8) & 0xF) * 2;
        op2 = (imm >> rot) | (imm << (32 - rot));
        if (rot != 0) {
            shifter_carry = (op2 >> 31) & 1;
        }
    } else {
        /* Register operand with shift */
        uint32_t rm = insn & 0xF;
        uint32_t shift_type = (insn >> 5) & 3;
        uint32_t shift_amount;
        bool reg_shift = (insn >> 4) & 1;

        uint32_t rm_val = r[rm];
        if (rm == REG_PC) rm_val += 4; /* PC ahead in register shift */

        if (reg_shift) {
            uint32_t rs = (insn >> 8) & 0xF;
            shift_amount = r[rs] & 0xFF;
        } else {
            shift_amount = (insn >> 7) & 0x1F;
        }
        op2 = BarrelShift(rm_val, shift_type, shift_amount, shifter_carry, reg_shift);
    }

    uint32_t rn_val = r[rn];
    if (rn == REG_PC) rn_val += 4; /* PC is ahead */

    uint32_t result = 0;
    bool write_rd = true;
    bool logic_op = false;

    switch (opcode) {
    case 0x0: /* AND */
        result = rn_val & op2;
        logic_op = true;
        break;
    case 0x1: /* EOR */
        result = rn_val ^ op2;
        logic_op = true;
        break;
    case 0x2: /* SUB */
        result = rn_val - op2;
        break;
    case 0x3: /* RSB */
        result = op2 - rn_val;
        break;
    case 0x4: /* ADD */
        result = rn_val + op2;
        break;
    case 0x5: /* ADC */
        result = rn_val + op2 + (GetC() ? 1 : 0);
        break;
    case 0x6: /* SBC */
        result = rn_val - op2 - (GetC() ? 0 : 1);
        break;
    case 0x7: /* RSC */
        result = op2 - rn_val - (GetC() ? 0 : 1);
        break;
    case 0x8: /* TST */
        result = rn_val & op2;
        write_rd = false;
        logic_op = true;
        break;
    case 0x9: /* TEQ */
        result = rn_val ^ op2;
        write_rd = false;
        logic_op = true;
        break;
    case 0xA: /* CMP */
        result = rn_val - op2;
        write_rd = false;
        break;
    case 0xB: /* CMN */
        result = rn_val + op2;
        write_rd = false;
        break;
    case 0xC: /* ORR */
        result = rn_val | op2;
        logic_op = true;
        break;
    case 0xD: /* MOV */
        result = op2;
        logic_op = true;
        break;
    case 0xE: /* BIC */
        result = rn_val & ~op2;
        logic_op = true;
        break;
    case 0xF: /* MVN */
        result = ~op2;
        logic_op = true;
        break;
    }

    if (S) {
        if (rd == REG_PC) {
            /* MOVS PC, LR => exception return */
            cpsr = spsr;
        } else {
            SetN((result >> 31) & 1);
            SetZ(result == 0);

            if (logic_op) {
                SetC(shifter_carry);
            } else {
                /* Arithmetic flags */
                switch (opcode) {
                case 0x2: /* SUB */
                case 0xA: /* CMP */
                    SetC(rn_val >= op2);
                    SetV(((rn_val ^ op2) & (rn_val ^ result)) >> 31);
                    break;
                case 0x3: /* RSB */
                    SetC(op2 >= rn_val);
                    SetV(((op2 ^ rn_val) & (op2 ^ result)) >> 31);
                    break;
                case 0x4: /* ADD */
                case 0xB: /* CMN */
                    SetC(result < rn_val);
                    SetV(((rn_val ^ ~op2) & (rn_val ^ result)) >> 31);
                    break;
                case 0x5: /* ADC */ {
                    uint64_t full = (uint64_t)rn_val + op2 + (GetC() ? 1 : 0);
                    SetC(full > 0xFFFFFFFF);
                    SetV(((rn_val ^ ~op2) & (rn_val ^ result)) >> 31);
                    break;
                }
                case 0x6: /* SBC */
                    SetC((uint64_t)rn_val >= (uint64_t)op2 + (GetC() ? 0 : 1));
                    SetV(((rn_val ^ op2) & (rn_val ^ result)) >> 31);
                    break;
                case 0x7: /* RSC */
                    SetC((uint64_t)op2 >= (uint64_t)rn_val + (GetC() ? 0 : 1));
                    SetV(((op2 ^ rn_val) & (op2 ^ result)) >> 31);
                    break;
                }
            }
        }
    }

    if (write_rd) {
        r[rd] = result;
        if (rd == REG_PC) {
            /* Branch via data processing (e.g. MOV PC, Rm) - check thunk handler */
            uint32_t target = result;
            if (thunk_handler && thunk_handler(target & ~1u, r, *mem)) {
                return;
            }
            /* Normal branch - check for Thumb interwork */
            if (target & 1) {
                cpsr |= PSR_T;
                r[REG_PC] = target & ~1u;
            } else {
                r[REG_PC] = target & ~3u;
            }
        }
    }
}

void ArmCpu::ArmMultiply(uint32_t insn) {
    bool A = (insn >> 21) & 1;  /* Accumulate */
    bool S = (insn >> 20) & 1;
    uint32_t rd = (insn >> 16) & 0xF;
    uint32_t rn = (insn >> 12) & 0xF;
    uint32_t rs = (insn >> 8) & 0xF;
    uint32_t rm = insn & 0xF;

    uint32_t result = r[rm] * r[rs];
    if (A) result += r[rn];

    r[rd] = result;
    if (S) SetNZ(result);
}

void ArmCpu::ArmMultiplyLong(uint32_t insn) {
    bool U = (insn >> 22) & 1;  /* Unsigned (0) / Signed (1) */
    bool A = (insn >> 21) & 1;
    bool S = (insn >> 20) & 1;
    uint32_t rdhi = (insn >> 16) & 0xF;
    uint32_t rdlo = (insn >> 12) & 0xF;
    uint32_t rs = (insn >> 8) & 0xF;
    uint32_t rm = insn & 0xF;

    uint64_t result;
    if (U) {
        result = (int64_t)(int32_t)r[rm] * (int64_t)(int32_t)r[rs];
    } else {
        result = (uint64_t)r[rm] * (uint64_t)r[rs];
    }

    if (A) {
        result += ((uint64_t)r[rdhi] << 32) | r[rdlo];
    }

    r[rdhi] = (uint32_t)(result >> 32);
    r[rdlo] = (uint32_t)result;

    if (S) {
        SetN((result >> 63) & 1);
        SetZ(result == 0);
    }
}

void ArmCpu::ArmSingleDataTransfer(uint32_t insn) {
    bool I = (insn >> 25) & 1;  /* Immediate offset (0) / Register (1) */
    bool P = (insn >> 24) & 1;  /* Pre/Post indexing */
    bool U = (insn >> 23) & 1;  /* Up/Down */
    bool B = (insn >> 22) & 1;  /* Byte/Word */
    bool W = (insn >> 21) & 1;  /* Write-back */
    bool L = (insn >> 20) & 1;  /* Load/Store */
    uint32_t rn = (insn >> 16) & 0xF;
    uint32_t rd = (insn >> 12) & 0xF;

    uint32_t offset;
    if (!I) {
        offset = insn & 0xFFF;
    } else {
        uint32_t rm = insn & 0xF;
        uint32_t shift_type = (insn >> 5) & 3;
        uint32_t shift_amount = (insn >> 7) & 0x1F;
        bool dummy;
        offset = BarrelShift(r[rm], shift_type, shift_amount, dummy, false);
    }

    uint32_t base = r[rn];
    if (rn == REG_PC) base += 4;

    uint32_t addr;
    if (P) {
        addr = U ? base + offset : base - offset;
    } else {
        addr = base;
    }

    /* Check for thunk addresses */
    if (L && thunk_handler) {
        uint32_t load_addr = addr;
        if (mem->IsValid(load_addr)) {
            /* Check what we're loading - might be a thunk pointer */
        }
    }

    if (L) {
        /* Load */
        if (B) {
            r[rd] = mem->Read8(addr);
        } else {
            uint32_t val = mem->Read32(addr & ~3u);
            /* Handle unaligned reads via rotation */
            uint32_t misalign = addr & 3;
            if (misalign) {
                val = (val >> (misalign * 8)) | (val << (32 - misalign * 8));
            }
            r[rd] = val;
        }
        if (rd == REG_PC) {
            /* Branch via load (e.g. LDR PC, [Rn]) - check thunk handler */
            uint32_t target = r[REG_PC];
            if (thunk_handler && thunk_handler(target & ~1u, r, *mem)) {
                return;
            }
            if (target & 1) {
                cpsr |= PSR_T;
                r[REG_PC] = target & ~1u;
            } else {
                r[REG_PC] = target & ~3u;
            }
        }
    } else {
        /* Store */
        uint32_t val = r[rd];
        if (rd == REG_PC) val += 4;
        if (B) {
            mem->Write8(addr, (uint8_t)val);
        } else {
            mem->Write32(addr & ~3u, val);
        }
    }

    /* Write-back / post-index */
    if (!P) {
        uint32_t new_base = U ? base + offset : base - offset;
        r[rn] = new_base;
    } else if (W) {
        r[rn] = addr;
    }
}

void ArmCpu::ArmHalfwordTransfer(uint32_t insn) {
    bool P = (insn >> 24) & 1;
    bool U = (insn >> 23) & 1;
    bool I = (insn >> 22) & 1;
    bool W = (insn >> 21) & 1;
    bool L = (insn >> 20) & 1;
    uint32_t rn = (insn >> 16) & 0xF;
    uint32_t rd = (insn >> 12) & 0xF;
    uint32_t sh = (insn >> 5) & 3;

    uint32_t offset;
    if (I) {
        offset = ((insn >> 4) & 0xF0) | (insn & 0xF);
    } else {
        offset = r[insn & 0xF];
    }

    uint32_t base = r[rn];
    if (rn == REG_PC) base += 4;

    uint32_t addr;
    if (P) {
        addr = U ? base + offset : base - offset;
    } else {
        addr = base;
    }

    if (L) {
        switch (sh) {
        case 1: /* LDRH */
            r[rd] = mem->Read16(addr);
            break;
        case 2: /* LDRSB */
            r[rd] = (int32_t)(int8_t)mem->Read8(addr);
            break;
        case 3: /* LDRSH */
            r[rd] = (int32_t)(int16_t)mem->Read16(addr);
            break;
        }
    } else {
        switch (sh) {
        case 1: /* STRH */
            mem->Write16(addr, (uint16_t)r[rd]);
            break;
        case 2: /* LDRD (ARMv5) - load doubleword */
            r[rd] = mem->Read32(addr);
            r[rd + 1] = mem->Read32(addr + 4);
            break;
        case 3: /* STRD (ARMv5) - store doubleword */
            mem->Write32(addr, r[rd]);
            mem->Write32(addr + 4, r[rd + 1]);
            break;
        }
    }

    if (!P) {
        r[rn] = U ? base + offset : base - offset;
    } else if (W) {
        r[rn] = addr;
    }
}

void ArmCpu::ArmBlockDataTransfer(uint32_t insn) {
    bool P = (insn >> 24) & 1;  /* Pre/Post */
    bool U = (insn >> 23) & 1;  /* Up/Down */
    bool S = (insn >> 22) & 1;  /* PSR / force user */
    bool W = (insn >> 21) & 1;  /* Write-back */
    bool L = (insn >> 20) & 1;  /* Load/Store */
    uint32_t rn = (insn >> 16) & 0xF;
    uint16_t reg_list = insn & 0xFFFF;

    uint32_t base = r[rn];
    int count = 0;
    for (int i = 0; i < 16; i++) {
        if (reg_list & (1 << i)) count++;
    }

    uint32_t addr;
    uint32_t writeback_val;

    if (U) {
        addr = P ? base + 4 : base;
        writeback_val = base + count * 4;
    } else {
        addr = P ? base - count * 4 : base - count * 4 + 4;
        writeback_val = base - count * 4;
    }

    for (int i = 0; i < 16; i++) {
        if (!(reg_list & (1 << i))) continue;

        if (L) {
            r[i] = mem->Read32(addr);
            if (i == REG_PC) {
                if (S) cpsr = spsr;  /* LDMFD with S bit = exception return */
                if (r[REG_PC] & 1) {
                    cpsr |= PSR_T;
                    r[REG_PC] &= ~1u;
                } else {
                    r[REG_PC] &= ~3u;
                }
            }
        } else {
            uint32_t val = r[i];
            if (i == REG_PC) val += 4;
            mem->Write32(addr, val);
        }
        addr += 4;
    }

    if (W) r[rn] = writeback_val;
}

void ArmCpu::ArmBranch(uint32_t insn) {
    bool link = (insn >> 24) & 1;
    int32_t offset = (int32_t)(insn << 8) >> 6; /* Sign-extend 24-bit offset, shift left 2 */

    if (link) {
        r[REG_LR] = r[REG_PC]; /* Return address (PC already advanced by 4) */
    }

    uint32_t target = r[REG_PC] + 4 + offset; /* +4 because ARM PC is 2 instructions ahead */

    /* Check for thunk */
    if (thunk_handler && thunk_handler(target, r, *mem)) {
        return;
    }

    r[REG_PC] = target;
}

void ArmCpu::ArmBranchExchange(uint32_t insn) {
    uint32_t rm = insn & 0xF;
    uint32_t target = r[rm];

    /* Check for thunk */
    if (thunk_handler && thunk_handler(target & ~1u, r, *mem)) {
        return;
    }

    if (target & 1) {
        cpsr |= PSR_T;
        r[REG_PC] = target & ~1u;
    } else {
        cpsr &= ~PSR_T;
        r[REG_PC] = target & ~3u;
    }
}

void ArmCpu::ArmSwap(uint32_t insn) {
    bool B = (insn >> 22) & 1;
    uint32_t rn = (insn >> 16) & 0xF;
    uint32_t rd = (insn >> 12) & 0xF;
    uint32_t rm = insn & 0xF;

    uint32_t addr = r[rn];
    if (B) {
        uint8_t tmp = mem->Read8(addr);
        mem->Write8(addr, (uint8_t)r[rm]);
        r[rd] = tmp;
    } else {
        uint32_t tmp = mem->Read32(addr);
        mem->Write32(addr, r[rm]);
        r[rd] = tmp;
    }
}

void ArmCpu::ArmSoftwareInterrupt(uint32_t insn) {
    uint32_t swi_num = insn & 0x00FFFFFF;
    fprintf(stderr, "[ARM] SWI #0x%X at PC=0x%08X\n", swi_num, r[REG_PC] - 4);

    /* Windows CE uses SWI for system calls - we handle these through thunks */
    if (thunk_handler) {
        /* Pass SWI number encoded as a special address */
        uint32_t swi_addr = 0xFFFF0000 | swi_num;
        if (thunk_handler(swi_addr, r, *mem)) return;
    }

    halted = true;
    halt_code = 2;
}

void ArmCpu::ArmMRS(uint32_t insn) {
    bool R = (insn >> 22) & 1; /* SPSR (1) or CPSR (0) */
    uint32_t rd = (insn >> 12) & 0xF;
    r[rd] = R ? spsr : cpsr;
}

void ArmCpu::ArmMSR(uint32_t insn) {
    bool R = (insn >> 22) & 1;
    bool I = (insn >> 25) & 1;

    uint32_t val;
    if (I) {
        uint32_t imm = insn & 0xFF;
        uint32_t rot = ((insn >> 8) & 0xF) * 2;
        val = (imm >> rot) | (imm << (32 - rot));
    } else {
        val = r[insn & 0xF];
    }

    /* Field mask */
    uint32_t mask = 0;
    if (insn & (1 << 16)) mask |= 0x000000FF; /* control */
    if (insn & (1 << 17)) mask |= 0x0000FF00; /* extension */
    if (insn & (1 << 18)) mask |= 0x00FF0000; /* status */
    if (insn & (1 << 19)) mask |= 0xFF000000; /* flags */

    if (R) {
        spsr = (spsr & ~mask) | (val & mask);
    } else {
        cpsr = (cpsr & ~mask) | (val & mask);
    }
}

void ArmCpu::ArmCLZ(uint32_t insn) {
    uint32_t rd = (insn >> 12) & 0xF;
    uint32_t rm = insn & 0xF;
    uint32_t val = r[rm];

    if (val == 0) {
        r[rd] = 32;
    } else {
        uint32_t count = 0;
        while (!(val & 0x80000000)) { val <<= 1; count++; }
        r[rd] = count;
    }
}
