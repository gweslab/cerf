#pragma once

/* Encodings: Intel SDM Vol. 2; ModR/M forms per Vol. 2A Table 2-2 (p. 2-6). */

#include "x86_emit.h"

namespace x86 {

/* ADD r/m32, imm32 - 81 /0 id, register-direct (SDM Vol. 2A 3-32 ADD). */
inline void EmitAddRegImm32(uint8_t*& c, uint8_t reg, uint32_t imm) {
    Emit8(c, 0x81);
    EmitModRmReg(c, 3, reg, 0);
    Emit32(c, imm);
}

/* ADD r32, r/m32 - 03 /r, register-direct (SDM Vol. 2A 3-32 ADD). */
inline void EmitAddReg32Reg32(uint8_t*& c, uint8_t dst, uint8_t src) {
    Emit8(c, 0x03);
    EmitModRmReg(c, 3, src, dst);
}

/* ADD r32, [base + disp32] - 03 /r mod=10 (SDM Vol. 2A 3-32 ADD). */
inline void EmitAddRegBaseDisp32(uint8_t*& c, uint8_t reg, uint8_t base,
                                 int32_t disp) {
    Emit8(c, 0x03);
    EmitModRmReg(c, 2, base, reg);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* ADD r/m32, imm8 (sign-extended) - 83 /0 ib mod=10
   (SDM Vol. 2A 3-32 ADD). */
inline void EmitAddBaseDisp32Imm8(uint8_t*& c, uint8_t base, int32_t disp,
                                  uint8_t imm8) {
    Emit8(c, 0x83);
    EmitModRmReg(c, 2, base, 0);
    Emit32(c, static_cast<uint32_t>(disp));
    Emit8(c, imm8);
}

/* ADC r/m32, imm8 (sign-extended) - 83 /2 ib mod=10
   (SDM Vol. 2A 3-27 ADC). */
inline void EmitAdcBaseDisp32Imm8(uint8_t*& c, uint8_t base, int32_t disp,
                                  uint8_t imm8) {
    Emit8(c, 0x83);
    EmitModRmReg(c, 2, base, 2);
    Emit32(c, static_cast<uint32_t>(disp));
    Emit8(c, imm8);
}

/* ADC r/m32, imm32 - 81 /2 id, register-direct (SDM Vol. 2A 3-27 ADC). */
inline void EmitAdcRegImm32(uint8_t*& c, uint8_t reg, uint32_t imm) {
    Emit8(c, 0x81);
    EmitModRmReg(c, 3, reg, 2);
    Emit32(c, imm);
}

/* ADC r32, r/m32 - 13 /r, register-direct (SDM Vol. 2A 3-27 ADC). */
inline void EmitAdcReg32Reg32(uint8_t*& c, uint8_t dst, uint8_t src) {
    Emit8(c, 0x13);
    EmitModRmReg(c, 3, src, dst);
}

/* ADC r32, [base + disp32] - 13 /r mod=10 (SDM Vol. 2A 3-27 ADC). */
inline void EmitAdcRegBaseDisp32(uint8_t*& c, uint8_t reg, uint8_t base,
                                 int32_t disp) {
    Emit8(c, 0x13);
    EmitModRmReg(c, 2, base, reg);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* SUB r/m32, imm32 - 81 /5 id, register-direct (SDM Vol. 2B 4-681 SUB). */
inline void EmitSubRegImm32(uint8_t*& c, uint8_t reg, uint32_t imm) {
    Emit8(c, 0x81);
    EmitModRmReg(c, 3, reg, 5);
    Emit32(c, imm);
}

/* SBB r/m32, imm32 - 81 /3 id, register-direct (SDM Vol. 2B 4-608 SBB). */
inline void EmitSbbRegImm32(uint8_t*& c, uint8_t reg, uint32_t imm) {
    Emit8(c, 0x81);
    EmitModRmReg(c, 3, reg, 3);
    Emit32(c, imm);
}

/* SBB r32, r/m32 - 1B /r, register-direct (SDM Vol. 2B 4-608 SBB). */
inline void EmitSbbReg32Reg32(uint8_t*& c, uint8_t dst, uint8_t src) {
    Emit8(c, 0x1B);
    EmitModRmReg(c, 3, src, dst);
}

/* SUB r32, r/m32 - 2B /r, register-direct (SDM Vol. 2B 4-681 SUB). */
inline void EmitSubReg32Reg32(uint8_t*& c, uint8_t dst, uint8_t src) {
    Emit8(c, 0x2B);
    EmitModRmReg(c, 3, src, dst);
}

/* SUB r32, [base + disp32] - 2B /r mod=10 (SDM Vol. 2B 4-681 SUB). */
inline void EmitSubRegBaseDisp32(uint8_t*& c, uint8_t reg, uint8_t base,
                                 int32_t disp) {
    Emit8(c, 0x2B);
    EmitModRmReg(c, 2, base, reg);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* SBB r32, [base + disp32] - 1B /r mod=10 (SDM Vol. 2B 4-608 SBB). */
inline void EmitSbbRegBaseDisp32(uint8_t*& c, uint8_t reg, uint8_t base,
                                 int32_t disp) {
    Emit8(c, 0x1B);
    EmitModRmReg(c, 2, base, reg);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* AND r/m32, imm32 - 81 /4 id, register-direct (SDM Vol. 2A 3-78 AND). */
inline void EmitAndRegImm32(uint8_t*& c, uint8_t reg, uint32_t imm) {
    Emit8(c, 0x81);
    EmitModRmReg(c, 3, reg, 4);
    Emit32(c, imm);
}

/* AND r32, r/m32 - 23 /r, register-direct (SDM Vol. 2A 3-78 AND). */
inline void EmitAndReg32Reg32(uint8_t*& c, uint8_t dst, uint8_t src) {
    Emit8(c, 0x23);
    EmitModRmReg(c, 3, src, dst);
}

/* AND r/m32, imm32 - 81 /4 id, mod=10 (SDM Vol. 2A 3-78 AND). */
inline void EmitAndBaseDisp32Imm32(uint8_t*& c, uint8_t base, int32_t disp,
                                   uint32_t imm) {
    Emit8(c, 0x81);
    EmitModRmReg(c, 2, base, 4);
    Emit32(c, static_cast<uint32_t>(disp));
    Emit32(c, imm);
}

/* OR r32, r/m32 - 0B /r, register-direct (SDM Vol. 2B 4-172 OR). */
inline void EmitOrReg32Reg32(uint8_t*& c, uint8_t dst, uint8_t src) {
    Emit8(c, 0x0B);
    EmitModRmReg(c, 3, src, dst);
}

/* OR r32, [base + disp32] - 0B /r mod=10 (SDM Vol. 2B 4-172 OR). */
inline void EmitOrRegBaseDisp32(uint8_t*& c, uint8_t reg, uint8_t base,
                                int32_t disp) {
    Emit8(c, 0x0B);
    EmitModRmReg(c, 2, base, reg);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* OR r/m32, imm32 - 81 /1 id, mod=10 (SDM Vol. 2B 4-172 OR). */
inline void EmitOrBaseDisp32Imm32(uint8_t*& c, uint8_t base, int32_t disp,
                                  uint32_t imm) {
    Emit8(c, 0x81);
    EmitModRmReg(c, 2, base, 1);
    Emit32(c, static_cast<uint32_t>(disp));
    Emit32(c, imm);
}

/* OR r/m32, imm32 - 81 /1 id, register-direct (SDM Vol. 2B 4-172 OR). */
inline void EmitOrRegImm32(uint8_t*& c, uint8_t reg, uint32_t imm) {
    Emit8(c, 0x81);
    EmitModRmReg(c, 3, reg, 1);
    Emit32(c, imm);
}

/* XOR r32, r/m32 - 33 /r, register-direct (SDM Vol. 2D 6-36 XOR). */
inline void EmitXorRegReg(uint8_t*& c, uint8_t dst, uint8_t src) {
    Emit8(c, 0x33);
    EmitModRmReg(c, 3, src, dst);
}

/* XOR r/m32, imm32 - 81 /6 id, register-direct (SDM Vol. 2D 6-36 XOR). */
inline void EmitXorRegImm32(uint8_t*& c, uint8_t reg, uint32_t imm) {
    Emit8(c, 0x81);
    EmitModRmReg(c, 3, reg, 6);
    Emit32(c, imm);
}

/* CMP r/m32, imm8 (sign-extended) - 83 /7 ib, register-direct
   (SDM Vol. 2A 3-179 CMP). */
inline void EmitCmpRegImm8(uint8_t*& c, uint8_t reg, uint8_t imm8) {
    Emit8(c, 0x83);
    EmitModRmReg(c, 3, reg, 7);
    Emit8(c, imm8);
}

/* CMP r/m32, imm32 - 81 /7 id, register-direct (SDM Vol. 2A 3-179 CMP). */
inline void EmitCmpRegImm32(uint8_t*& c, uint8_t reg, uint32_t imm) {
    Emit8(c, 0x81);
    EmitModRmReg(c, 3, reg, 7);
    Emit32(c, imm);
}

/* CMP r32, r/m32 - 3B /r mod=10 (SDM Vol. 2A 3-179 CMP). */
inline void EmitCmpRegBaseDisp32(uint8_t*& c, uint8_t reg, uint8_t base,
                                 int32_t disp) {
    Emit8(c, 0x3B);
    EmitModRmReg(c, 2, base, reg);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* CMP r8, r/m8 - 3A /r mod=10 (SDM Vol. 2A 3-179 CMP). */
inline void EmitCmpReg8BaseDisp32(uint8_t*& c, uint8_t reg8, uint8_t base,
                                  int32_t disp) {
    Emit8(c, 0x3A);
    EmitModRmReg(c, 2, base, reg8);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* TEST r/m32, r32 - 85 /r, register-direct (SDM Vol. 2B 4-711 TEST). */
inline void EmitTestRegReg(uint8_t*& c, uint8_t a, uint8_t b) {
    Emit8(c, 0x85);
    EmitModRmReg(c, 3, a, b);
}

/* TEST r/m32, imm32 - F7 /0 id, register-direct (SDM Vol. 2B 4-711 TEST). */
inline void EmitTestRegImm32(uint8_t*& c, uint8_t reg, uint32_t imm) {
    Emit8(c, 0xF7);
    EmitModRmReg(c, 3, reg, 0);
    Emit32(c, imm);
}

/* TEST r/m8, imm8 - F6 /0 ib mod=10 (SDM Vol. 2B 4-711 TEST). */
inline void EmitTestByteBaseDisp32Imm8(uint8_t*& c, uint8_t base, int32_t disp,
                                       uint8_t imm8) {
    Emit8(c, 0xF6);
    EmitModRmReg(c, 2, base, 0);
    Emit32(c, static_cast<uint32_t>(disp));
    Emit8(c, imm8);
}

/* BT r/m32, r32 - 0F A3 /r, mod=00 [base] (SDM Vol. 2A 3-130 BT). */
inline void EmitBtMemReg(uint8_t*& c, uint8_t base, uint8_t reg) {
    Emit8(c, 0x0F);
    Emit8(c, 0xA3);
    EmitModRmReg(c, 0, base, reg);
}

/* BTS r/m32, r32 - 0F AB /r, mod=00 [base] (SDM Vol. 2A 3-136 BTS). */
inline void EmitBtsMemReg(uint8_t*& c, uint8_t base, uint8_t reg) {
    Emit8(c, 0x0F);
    Emit8(c, 0xAB);
    EmitModRmReg(c, 0, base, reg);
}

/* BT r/m32, imm8 - 0F BA /4 ib, register-direct; a register bit base
   takes the offset modulo 32 (SDM Vol. 2A 3-130 BT). */
inline void EmitBtRegImm8(uint8_t*& c, uint8_t reg, uint8_t bit) {
    Emit8(c, 0x0F);
    Emit8(c, 0xBA);
    EmitModRmReg(c, 3, reg, 4);
    Emit8(c, bit);
}

/* SETcc second opcode bytes - SDM Vol. 2B 4-618/4-619 SETcc. */
constexpr uint8_t kSetO  = 0x90;  /* OF = 1 */
constexpr uint8_t kSetC  = 0x92;  /* CF = 1 */
constexpr uint8_t kSetNc = 0x93;  /* CF = 0 */
constexpr uint8_t kSetZ  = 0x94;  /* ZF = 1 */
constexpr uint8_t kSetNz = 0x95;  /* ZF = 0 */
constexpr uint8_t kSetS  = 0x98;  /* SF = 1 */

/* SETcc r8 - 0F 90+cc, mod=11 register-direct; operand encoding M is
   ModRM:r/m alone, so the reg field is unused (SDM Vol. 2B 4-619). */
inline void EmitSetccReg8(uint8_t*& c, uint8_t setcc_opcode, uint8_t reg8) {
    Emit8(c, 0x0F);
    Emit8(c, setcc_opcode);
    EmitModRmReg(c, 3, reg8, 0);
}

/* SETcc r/m8 - 0F 90+cc, mod=10 [base+disp32]. Operand encoding M is
   ModRM:r/m alone, so the reg field is unused, and "the destination operand
   points to a byte register or a byte in memory" (SDM Vol. 2B 4-619). */
inline void EmitSetccBaseDisp32(uint8_t*& c, uint8_t setcc_opcode,
                                uint8_t base, int32_t disp) {
    Emit8(c, 0x0F);
    Emit8(c, setcc_opcode);
    EmitModRmReg(c, 2, base, 0);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* MOV r/m8, imm8 - C6 /0 ib, mod=10 (SDM Vol. 2B 4-35 MOV). */
inline void EmitMovByteBaseDisp32Imm8(uint8_t*& c, uint8_t base, int32_t disp,
                                      uint8_t imm8) {
    Emit8(c, 0xC6);
    EmitModRmReg(c, 2, base, 0);
    Emit32(c, static_cast<uint32_t>(disp));
    Emit8(c, imm8);
}

/* MOV r8, r/m8 - 8A /r, mod=10 (SDM Vol. 2B 4-35 MOV). */
inline void EmitMovByteRegBaseDisp32(uint8_t*& c, uint8_t reg8, uint8_t base,
                                     int32_t disp) {
    Emit8(c, 0x8A);
    EmitModRmReg(c, 2, base, reg8);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* CMP r/m8, imm8 - 80 /7 ib, mod=10 (SDM Vol. 2A 3-179 CMP). */
inline void EmitCmpByteBaseDisp32Imm8(uint8_t*& c, uint8_t base, int32_t disp,
                                      uint8_t imm8) {
    Emit8(c, 0x80);
    EmitModRmReg(c, 2, base, 7);
    Emit32(c, static_cast<uint32_t>(disp));
    Emit8(c, imm8);
}

/* CMP r/m8, imm8 - 80 /7 ib, register-direct (SDM Vol. 2A 3-179 CMP). */
inline void EmitCmpReg8Imm8(uint8_t*& c, uint8_t reg8, uint8_t imm8) {
    Emit8(c, 0x80);
    EmitModRmReg(c, 3, reg8, 7);
    Emit8(c, imm8);
}

/* XOR r8, r/m8 - 32 /r, mod=10 (SDM Vol. 2D 6-36 XOR). */
inline void EmitXorByteRegBaseDisp32(uint8_t*& c, uint8_t reg8, uint8_t base,
                                     int32_t disp) {
    Emit8(c, 0x32);
    EmitModRmReg(c, 2, base, reg8);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* SUB r8, r/m8 - 2A /r, mod=10 (SDM Vol. 2B 4-681 SUB). */
inline void EmitSubByteRegBaseDisp32(uint8_t*& c, uint8_t reg8, uint8_t base,
                                     int32_t disp) {
    Emit8(c, 0x2A);
    EmitModRmReg(c, 2, base, reg8);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* OR r8, r/m8 - 0A /r, mod=10 (SDM Vol. 2B 4-172 OR). */
inline void EmitOrByteRegBaseDisp32(uint8_t*& c, uint8_t reg8, uint8_t base,
                                    int32_t disp) {
    Emit8(c, 0x0A);
    EmitModRmReg(c, 2, base, reg8);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* SHL r/m32, imm8 - C1 /4 ib, register-direct (SDM Vol. 2B 4-600 SHL). */
inline void EmitShlReg32Imm(uint8_t*& c, uint8_t reg, uint8_t imm8) {
    Emit8(c, 0xC1);
    EmitModRmReg(c, 3, reg, 4);
    Emit8(c, imm8);
}

/* SHL r/m32, CL - D3 /4, register-direct; count masked to 5 bits, and
   "If the count is 0, the flags are not affected" (SDM Vol. 2B 4-600,
   4-602 SHL). */
inline void EmitShlReg32Cl(uint8_t*& c, uint8_t reg) {
    Emit8(c, 0xD3);
    EmitModRmReg(c, 3, reg, 4);
}

/* SHR r/m32, CL - D3 /5, register-direct (SDM Vol. 2B 4-600 SHR). */
inline void EmitShrReg32Cl(uint8_t*& c, uint8_t reg) {
    Emit8(c, 0xD3);
    EmitModRmReg(c, 3, reg, 5);
}

/* SAR r/m32, CL - D3 /7, register-direct (SDM Vol. 2B 4-599 SAR). */
inline void EmitSarReg32Cl(uint8_t*& c, uint8_t reg) {
    Emit8(c, 0xD3);
    EmitModRmReg(c, 3, reg, 7);
}

/* SHR r/m32, imm8 - C1 /5 ib, register-direct (SDM Vol. 2B 4-600 SHR). */
inline void EmitShrReg32Imm(uint8_t*& c, uint8_t reg, uint8_t imm8) {
    Emit8(c, 0xC1);
    EmitModRmReg(c, 3, reg, 5);
    Emit8(c, imm8);
}

/* SAR r/m32, imm8 - C1 /7 ib, register-direct (SDM Vol. 2B 4-599 SAR). */
inline void EmitSarReg32Imm(uint8_t*& c, uint8_t reg, uint8_t imm8) {
    Emit8(c, 0xC1);
    EmitModRmReg(c, 3, reg, 7);
    Emit8(c, imm8);
}

/* ROR r/m32, imm8 - C1 /1 ib, register-direct
   (SDM Vol. 2B 4-533 RCL/RCR/ROL/ROR). */
inline void EmitRorReg32Imm(uint8_t*& c, uint8_t reg, uint8_t imm8) {
    Emit8(c, 0xC1);
    EmitModRmReg(c, 3, reg, 1);
    Emit8(c, imm8);
}

/* ROR r/m32, CL - D3 /1, register-direct
   (SDM Vol. 2B 4-533 RCL/RCR/ROL/ROR). */
inline void EmitRorReg32Cl(uint8_t*& c, uint8_t reg) {
    Emit8(c, 0xD3);
    EmitModRmReg(c, 3, reg, 1);
}

/* SHRD r/m32, r32, imm8 - 0F AC /r ib, register-direct: shift dst right
   imm8 places, filling from src on the left (SDM Vol. 2B 4-638 SHRD). */
inline void EmitShrdReg32Reg32Imm8(uint8_t*& c, uint8_t dst, uint8_t src,
                                   uint8_t imm8) {
    Emit8(c, 0x0F);
    Emit8(c, 0xAC);
    EmitModRmReg(c, 3, dst, src);
    Emit8(c, imm8);
}

/* RCR r/m32, 1 - D1 /3, register-direct, "Rotate 33 bits (CF, r/m32)
   right once" (SDM Vol. 2B 4-532 RCL/RCR/ROL/ROR). */
inline void EmitRcrReg32By1(uint8_t*& c, uint8_t reg) {
    Emit8(c, 0xD1);
    EmitModRmReg(c, 3, reg, 3);
}

/* BSWAP r32 - 0F C8+rd (SDM Vol. 2A 3-129 BSWAP). */
inline void EmitBswapReg32(uint8_t*& c, uint8_t reg) {
    Emit8(c, 0x0F);
    Emit8(c, static_cast<uint8_t>(0xC8 + reg));
}

/* NOT r/m32 - F7 /2, mod=10 (SDM Vol. 2B 4-170 NOT). */
inline void EmitNotBaseDisp32(uint8_t*& c, uint8_t base, int32_t disp) {
    Emit8(c, 0xF7);
    EmitModRmReg(c, 2, base, 2);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* NOT r/m32 - F7 /2, register-direct, "Flags Affected: None"
   (SDM Vol. 2B 4-170 NOT). */
inline void EmitNotReg32(uint8_t*& c, uint8_t reg) {
    Emit8(c, 0xF7);
    EmitModRmReg(c, 3, reg, 2);
}

/* NEG r/m32 - F7 /3, register-direct: "The CF flag set to 0 if the source
   operand is 0; otherwise it is set to 1" (SDM Vol. 2B 4-167 NEG). */
inline void EmitNegReg32(uint8_t*& c, uint8_t reg) {
    Emit8(c, 0xF7);
    EmitModRmReg(c, 3, reg, 3);
}

/* MUL r/m32 - F7 /4, register-direct, EDX:EAX := EAX * r/m32 unsigned
   (SDM Vol. 2B 4-150 MUL). */
inline void EmitMulReg32(uint8_t*& c, uint8_t reg) {
    Emit8(c, 0xF7);
    EmitModRmReg(c, 3, reg, 4);
}

/* IMUL r/m32 - F7 /5, register-direct, EDX:EAX := EAX * r/m32 signed
   (SDM Vol. 2A 3-500 IMUL). */
inline void EmitImulReg32(uint8_t*& c, uint8_t reg) {
    Emit8(c, 0xF7);
    EmitModRmReg(c, 3, reg, 5);
}

/* IMUL r32, r/m32 - 0F AF /r, register-direct, dst := low doubleword of
   the product (SDM Vol. 2A 3-500 IMUL). */
inline void EmitImulReg32Reg32(uint8_t*& c, uint8_t dst, uint8_t src) {
    Emit8(c, 0x0F);
    Emit8(c, 0xAF);
    EmitModRmReg(c, 3, src, dst);
}

/* IMUL r32, r/m32, imm32 - 69 /r id, mod=11 register-direct; operand
   encoding RMI is ModRM:reg (destination), ModRM:r/m (source), imm32, and
   the product is truncated to the destination width (SDM Vol. 2A 3-500). */
inline void EmitImulReg32Reg32Imm32(uint8_t*& c, uint8_t dst, uint8_t src,
                                    uint32_t imm32) {
    Emit8(c, 0x69);
    EmitModRmReg(c, 3, src, dst);
    Emit32(c, imm32);
}

/* CDQ - 99, EDX:EAX = sign-extend of EAX (SDM Vol. 2A 3-314 CWD/CDQ/CQO). */
inline void EmitCdq(uint8_t*& c) {
    Emit8(c, 0x99);
}

/* CMC - F5, CF := NOT CF (SDM Vol. 2A 3-174 CMC). */
inline void EmitCmc(uint8_t*& c) {
    Emit8(c, 0xF5);
}

}  // namespace x86
