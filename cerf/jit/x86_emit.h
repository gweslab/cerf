#pragma once

/* Encodings: Intel SDM Vol. 2; ModR/M forms per Vol. 2A Table 2-2 (p. 2-6). */

#include <cstdint>
#include <cstring>

#include "../core/log.h"

namespace x86 {

/* r32 / r8 field encodings - SDM Vol. 2A Table 2-2. */
constexpr uint8_t kEax = 0;
constexpr uint8_t kEcx = 1;
constexpr uint8_t kEdx = 2;
constexpr uint8_t kEbx = 3;
constexpr uint8_t kEsp = 4;
constexpr uint8_t kEbp = 5;
constexpr uint8_t kEsi = 6;
constexpr uint8_t kEdi = 7;

constexpr uint8_t kMmuReg   = kEbx;
constexpr uint8_t kStateReg = kEsi;

constexpr uint8_t kAl = 0;
constexpr uint8_t kCl = 1;
constexpr uint8_t kDl = 2;

inline void Emit8(uint8_t*& c, uint8_t v) {
    *c++ = v;
}

inline void Emit32(uint8_t*& c, uint32_t v) {
    std::memcpy(c, &v, 4);
    c += 4;
}

/* ModR/M byte = (mod << 6) | (reg << 3) | r/m - SDM Vol. 2A Table 2-2. */
inline void EmitModRmByte(uint8_t*& c, uint8_t mod, uint8_t rm, uint8_t reg) {
    Emit8(c, static_cast<uint8_t>((mod << 6) | (reg << 3) | rm));
}

/* Per Table 2-2 notes 1-2: in the memory forms, r/m = 100b means a SIB
   byte follows, and mod = 00b with r/m = 101b means bare disp32. */
inline void EmitModRmReg(uint8_t*& c, uint8_t mod, uint8_t rm, uint8_t reg) {
    if (mod != 3u && rm == kEsp) {
        LOG(Caution, "x86 emit: r/m=100b in a memory form requires a SIB "
                "byte (mod=%u)\n", mod);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    if (mod == 0u && rm == kEbp) {
        LOG(Caution, "x86 emit: mod=00b r/m=101b encodes disp32, not "
                "[EBP]\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    EmitModRmByte(c, mod, rm, reg);
}

/* mod = 00b, r/m = 101b - bare disp32 (SDM Vol. 2A Table 2-2 note 2). */
inline void EmitModRmDisp32(uint8_t*& c, uint8_t reg) {
    EmitModRmByte(c, 0, kEbp, reg);
}

/* rel32 - displacement relative to the next instruction:
   SDM Vol. 2A 3-139 CALL, 3-552 JMP. */
inline void EmitOpcodeRel32(uint8_t*& c, uint8_t opcode, const void* target) {
    Emit8(c, opcode);
    Emit32(c, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(target) -
                                    reinterpret_cast<uintptr_t>(c + 4)));
}

/* CALL rel32 - E8 cd (SDM Vol. 2A 3-139 CALL). */
inline void EmitCall(uint8_t*& c, const void* target) {
    EmitOpcodeRel32(c, 0xE8, target);
}

/* JMP rel32 - E9 cd (SDM Vol. 2A 3-552 JMP). */
inline void EmitJmp32(uint8_t*& c, const void* target) {
    EmitOpcodeRel32(c, 0xE9, target);
}

/* RET - C3, Op/En ZO (SDM Vol. 2B 4-564 RET). */
inline void EmitRet(uint8_t*& c) {
    Emit8(c, 0xC3);
}

inline uint8_t* EmitRel8Label(uint8_t*& c, uint8_t opcode) {
    Emit8(c, opcode);
    uint8_t* label = c;
    Emit8(c, 0);
    return label;
}

inline uint8_t* EmitRel32Label(uint8_t*& c, uint8_t opcode0F) {
    Emit8(c, 0x0F);
    Emit8(c, opcode0F);
    uint8_t* label = c;
    Emit32(c, 0);
    return label;
}

/* JMP rel8 - EB cb (SDM Vol. 2A 3-552 JMP). */
inline uint8_t* EmitJmpLabel(uint8_t*& c) { return EmitRel8Label(c, 0xEB); }

/* JMP rel32 - E9 cd (SDM Vol. 2A 3-552 JMP). */
inline uint8_t* EmitJmpLabel32(uint8_t*& c) {
    Emit8(c, 0xE9);
    uint8_t* label = c;
    Emit32(c, 0);
    return label;
}

/* Jcc rel8 - 7x cb; Jcc rel32 - 0F 8x cd (SDM Vol. 2A 3-547..3-549 Jcc). */
inline uint8_t* EmitJzLabel(uint8_t*& c)    { return EmitRel8Label(c, 0x74); }
inline uint8_t* EmitJnzLabel(uint8_t*& c)   { return EmitRel8Label(c, 0x75); }
inline uint8_t* EmitJnoLabel(uint8_t*& c)   { return EmitRel8Label(c, 0x71); }
inline uint8_t* EmitJgeLabel(uint8_t*& c)   { return EmitRel8Label(c, 0x7D); }
inline uint8_t* EmitJleLabel(uint8_t*& c)   { return EmitRel8Label(c, 0x7E); }
inline uint8_t* EmitJzLabel32(uint8_t*& c)  { return EmitRel32Label(c, 0x84); }
inline uint8_t* EmitJnzLabel32(uint8_t*& c) { return EmitRel32Label(c, 0x85); }
inline uint8_t* EmitJsLabel32(uint8_t*& c)  { return EmitRel32Label(c, 0x88); }
inline uint8_t* EmitJaeLabel32(uint8_t*& c) { return EmitRel32Label(c, 0x83); }
inline uint8_t* EmitJncLabel32(uint8_t*& c) { return EmitJaeLabel32(c); }
inline uint8_t* EmitJbLabel32(uint8_t*& c)  { return EmitRel32Label(c, 0x82); }

/* rel8 - sign-extended 8-bit displacement: SDM Vol. 2A 3-552 JMP (EB cb),
   3-547 Jcc (7x cb). */
inline void FixupLabel(uint8_t* label, uint8_t* cursor) {
    const ptrdiff_t disp = cursor - (label + 1);
    if (disp < -128 || disp > 127) {
        LOG(Caution, "x86 emit: rel8 fixup out of range - opcode 0x%02X, "
                "displacement %d\n", label[-1], static_cast<int>(disp));
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    label[0] = static_cast<uint8_t>(disp);
}

inline void FixupLabel32(uint8_t* label, uint8_t* cursor) {
    const uint32_t disp = static_cast<uint32_t>(cursor - (label + 4));
    std::memcpy(label, &disp, 4);
}

/* MOV r32, imm32 - B8+rd id (SDM Vol. 2B 4-35 MOV). */
inline void EmitMovRegImm32(uint8_t*& c, uint8_t reg, uint32_t imm) {
    Emit8(c, static_cast<uint8_t>(0xB8 + reg));
    Emit32(c, imm);
}

/* MOV r32, r/m32 - 8B /r, register-direct (SDM Vol. 2B 4-35 MOV). */
inline void EmitMovRegReg(uint8_t*& c, uint8_t dst, uint8_t src) {
    Emit8(c, 0x8B);
    EmitModRmReg(c, 3, src, dst);
}

/* MOV r32, [base + disp32] - 8B /r mod=10 (SDM Vol. 2B 4-35 MOV). */
inline void EmitMovRegBaseDisp32(uint8_t*& c, uint8_t reg, uint8_t base,
                                 int32_t disp) {
    Emit8(c, 0x8B);
    EmitModRmReg(c, 2, base, reg);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* MOV [base + disp32], r32 - 89 /r mod=10 (SDM Vol. 2B 4-35 MOV). */
inline void EmitMovBaseDisp32Reg(uint8_t*& c, uint8_t base, int32_t disp,
                                 uint8_t reg) {
    Emit8(c, 0x89);
    EmitModRmReg(c, 2, base, reg);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* MOV r/m32, imm32 - C7 /0 id, mod=10 (SDM Vol. 2B 4-35 MOV). */
inline void EmitMovBaseDisp32Imm32(uint8_t*& c, uint8_t base, int32_t disp,
                                   uint32_t imm) {
    Emit8(c, 0xC7);
    EmitModRmReg(c, 2, base, 0);
    Emit32(c, static_cast<uint32_t>(disp));
    Emit32(c, imm);
}

/* MOV r/m8, r8 - 88 /r mod=10 (SDM Vol. 2B 4-35 MOV). */
inline void EmitMovBaseDisp32Byte(uint8_t*& c, uint8_t base, int32_t disp,
                                  uint8_t reg8) {
    Emit8(c, 0x88);
    EmitModRmReg(c, 2, base, reg8);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* MOV [disp32], r32 - 89 /r, mod=00 r/m=101 = bare disp32
   (SDM Vol. 2B 4-35 MOV; Vol. 2A Table 2-2 note 2). */
inline void EmitMovDwordPtrReg(uint8_t*& c, const void* addr, uint8_t reg) {
    Emit8(c, 0x89);
    EmitModRmDisp32(c, reg);
    Emit32(c, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(addr)));
}

/* MOV [disp32], imm32 - C7 /0 id, mod=00 r/m=101 = bare disp32
   (SDM Vol. 2B 4-35 MOV; Vol. 2A Table 2-2 note 2). */
inline void EmitMovDwordPtrImm32(uint8_t*& c, const void* addr, uint32_t imm) {
    Emit8(c, 0xC7);
    EmitModRmDisp32(c, 0);
    Emit32(c, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(addr)));
    Emit32(c, imm);
}

/* MOVSX r32, r/m8 - 0F BE /r mod=10 (SDM Vol. 2B 4-130 MOVSX). */
inline void EmitMovsxByteRegBaseDisp32(uint8_t*& c, uint8_t reg, uint8_t base,
                                       int32_t disp) {
    Emit8(c, 0x0F);
    Emit8(c, 0xBE);
    EmitModRmReg(c, 2, base, reg);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* MOVSX r32, r/m8 - 0F BE /r, register-direct (SDM Vol. 2B 4-130 MOVSX). */
inline void EmitMovsxReg32Reg8(uint8_t*& c, uint8_t dst, uint8_t src8) {
    Emit8(c, 0x0F);
    Emit8(c, 0xBE);
    EmitModRmReg(c, 3, src8, dst);
}

/* MOVSX r32, r/m16 - 0F BF /r, register-direct (SDM Vol. 2B 4-130 MOVSX). */
inline void EmitMovsxReg32Reg16(uint8_t*& c, uint8_t dst, uint8_t src16) {
    Emit8(c, 0x0F);
    Emit8(c, 0xBF);
    EmitModRmReg(c, 3, src16, dst);
}

/* MOVZX r32, r/m8 - 0F B6 /r, register-direct (SDM Vol. 2B 4-140 MOVZX). */
inline void EmitMovzxReg32Reg8(uint8_t*& c, uint8_t dst, uint8_t src8) {
    Emit8(c, 0x0F);
    Emit8(c, 0xB6);
    EmitModRmReg(c, 3, src8, dst);
}

/* MOVZX r32, r/m16 - 0F B7 /r, register-direct (SDM Vol. 2B 4-140 MOVZX). */
inline void EmitMovzxReg32Reg16(uint8_t*& c, uint8_t dst, uint8_t src16) {
    Emit8(c, 0x0F);
    Emit8(c, 0xB7);
    EmitModRmReg(c, 3, src16, dst);
}

/* LEA r32, m - 8D /r mod=10 (SDM Vol. 2A 3-594 LEA). */
inline void EmitLeaRegBaseDisp32(uint8_t*& c, uint8_t reg, uint8_t base,
                                 int32_t disp) {
    Emit8(c, 0x8D);
    EmitModRmReg(c, 2, base, reg);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* PUSH imm32 - 68 id (SDM Vol. 2B 4-521 PUSH). */
inline void EmitPush32(uint8_t*& c, uint32_t imm) {
    Emit8(c, 0x68);
    Emit32(c, imm);
}

/* PUSH r32 - 50+rd (SDM Vol. 2B 4-521 PUSH). */
inline void EmitPushReg(uint8_t*& c, uint8_t reg) {
    Emit8(c, static_cast<uint8_t>(0x50 + reg));
}

/* PUSH r/m32 - FF /6 mod=10 (SDM Vol. 2B 4-521 PUSH). */
inline void EmitPushBaseDisp32(uint8_t*& c, uint8_t base, int32_t disp) {
    Emit8(c, 0xFF);
    EmitModRmReg(c, 2, base, 6);
    Emit32(c, static_cast<uint32_t>(disp));
}

/* POP r32 - 58+rd (SDM Vol. 2B 4-398 POP). */
inline void EmitPopReg(uint8_t*& c, uint8_t reg) {
    Emit8(c, static_cast<uint8_t>(0x58 + reg));
}

}  // namespace x86
