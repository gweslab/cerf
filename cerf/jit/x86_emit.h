#pragma once

#include <cstdint>
#include <cstring>

#include "../core/log.h"

/* x86 (Win32) machine-code emit helpers. Header-only inline functions
   advancing a uint8_t*& cursor past the emitted bytes. Encodings come
   from the Intel 64 and IA-32 Architectures Software Developer's
   Manual Vol. 2 (instruction set reference). */

namespace x86 {

constexpr uint8_t kEax = 0;
constexpr uint8_t kEcx = 1;
constexpr uint8_t kEdx = 2;
constexpr uint8_t kEbx = 3;
constexpr uint8_t kEsp = 4;
constexpr uint8_t kEbp = 5;
constexpr uint8_t kEsi = 6;
constexpr uint8_t kEdi = 7;

/* 8-bit register encodings: AL/CL/DL/BL share the slot with their
   32-bit counterparts; AH/CH/DH/BH use slots 4-7 in the no-REX form. */
constexpr uint8_t kAl = kEax;
constexpr uint8_t kCl = kEcx;
constexpr uint8_t kDl = kEdx;
constexpr uint8_t kBl = kEbx;
constexpr uint8_t kAh = 4;
constexpr uint8_t kCh = 5;
constexpr uint8_t kDh = 6;
constexpr uint8_t kBh = 7;

/* Raw byte / halfword / dword emit. */
inline void Emit8 (uint8_t*& p, uint8_t  b) { *p++ = b; }
inline void Emit16(uint8_t*& p, uint16_t h) { std::memcpy(p, &h, 2); p += 2; }
inline void Emit32(uint8_t*& p, uint32_t w) { std::memcpy(p, &w, 4); p += 4; }
inline void EmitPtr(uint8_t*& p, const void* ptr) {
    Emit32(p, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ptr)));
}
inline void EmitRel32(uint8_t*& p, const void* target) {
    const uintptr_t rel = reinterpret_cast<uintptr_t>(target) -
                          reinterpret_cast<uintptr_t>(p) - 4u;
    Emit32(p, static_cast<uint32_t>(rel));
}

/* ModR/M byte (Intel SDM Vol. 2 §2.1.5 Table 2-2) and SIB byte
   (§2.1.5 Table 2-3). */
inline void EmitModRmReg(uint8_t*& p, uint8_t mod, uint8_t rm, uint8_t reg) {
    Emit8(p, static_cast<uint8_t>((mod << 6) | (reg << 3) | rm));
}
inline void EmitSib(uint8_t*& p, uint8_t ss, uint8_t index, uint8_t base) {
    Emit8(p, static_cast<uint8_t>((ss << 6) | (index << 3) | base));
}

inline void EmitSize16(uint8_t*& p) { Emit8(p, 0x66); }

/* MOV r32, [disp32] — uses the A1 short form for EAX, 8B /r otherwise. */
inline void EmitMovRegDwordPtr(uint8_t*& p, uint8_t reg, const void* ptr) {
    if (reg == kEax) { Emit8(p, 0xA1); EmitPtr(p, ptr); }
    else             { Emit8(p, 0x8B); EmitModRmReg(p, 0, 5, reg); EmitPtr(p, ptr); }
}

/* MOV r8, [disp32] — A0 short form for AL, 8A /r otherwise. */
inline void EmitMovRegBytePtr(uint8_t*& p, uint8_t reg, const void* ptr) {
    if (reg == kAl) { Emit8(p, 0xA0); EmitPtr(p, ptr); }
    else            { Emit8(p, 0x8A); EmitModRmReg(p, 0, 5, reg); EmitPtr(p, ptr); }
}

/* MOV [disp32], r32 — A3 short form for EAX, 89 /r otherwise. */
inline void EmitMovDwordPtrReg(uint8_t*& p, const void* ptr, uint8_t reg) {
    if (reg == kEax) { Emit8(p, 0xA3); EmitPtr(p, ptr); }
    else             { Emit8(p, 0x89); EmitModRmReg(p, 0, 5, reg); EmitPtr(p, ptr); }
}

/* MOV r32, imm32 — B8+rd, id. */
inline void EmitMovRegImm32(uint8_t*& p, uint8_t reg, uint32_t imm) {
    Emit8(p, static_cast<uint8_t>(0xB8 + reg));
    Emit32(p, imm);
}

/* MOV r32, r32 — 8B /r, mod=11. */
inline void EmitMovRegReg(uint8_t*& p, uint8_t dst, uint8_t src) {
    Emit8(p, 0x8B); EmitModRmReg(p, 3, src, dst);
}

/* CALL rel32 — E8 cd. */
inline void EmitCall(uint8_t*& p, const void* target) {
    Emit8(p, 0xE8); EmitRel32(p, target);
}

/* JMP rel32 — E9 cd. */
inline void EmitJmp32(uint8_t*& p, const void* target) {
    Emit8(p, 0xE9); EmitRel32(p, target);
}

/* RETN imm16 / RETN (Intel SDM C2 iw / C3). */
inline void EmitRetn(uint8_t*& p, uint16_t imm) {
    if (imm) { Emit8(p, 0xC2); Emit16(p, imm); }
    else     { Emit8(p, 0xC3); }
}

inline void EmitXorRegReg(uint8_t*& p, uint8_t r1, uint8_t r2) {
    Emit8(p, 0x33); EmitModRmReg(p, 3, r2, r1);
}
inline void EmitCmc(uint8_t*& p) { Emit8(p, 0xF5); }

/* Short conditional / unconditional jumps with 1-byte displacement.
   Each *Label form emits a 0-displacement back-patch slot and
   returns the address one past the displacement byte; FixupLabel
   writes the actual offset into the slot once the target is known. */
inline uint8_t* EmitJzLabel (uint8_t*& p) { Emit8(p, 0x74); Emit8(p, 0); return p; }
inline uint8_t* EmitJnzLabel(uint8_t*& p) { Emit8(p, 0x75); Emit8(p, 0); return p; }
inline uint8_t* EmitJbLabel (uint8_t*& p) { Emit8(p, 0x72); Emit8(p, 0); return p; }
inline uint8_t* EmitJbeLabel(uint8_t*& p) { Emit8(p, 0x76); Emit8(p, 0); return p; }
inline uint8_t* EmitJaLabel (uint8_t*& p) { Emit8(p, 0x77); Emit8(p, 0); return p; }
inline uint8_t* EmitJnoLabel(uint8_t*& p) { Emit8(p, 0x71); Emit8(p, 0); return p; }
inline uint8_t* EmitJncLabel(uint8_t*& p) { Emit8(p, 0x73); Emit8(p, 0); return p; }
inline uint8_t* EmitJcLabel (uint8_t*& p) { return EmitJbLabel(p); }
inline uint8_t* EmitJmpLabel(uint8_t*& p) { Emit8(p, 0xEB); Emit8(p, 0); return p; }

inline void FixupLabel(uint8_t* label, uint8_t* target) {
    const ptrdiff_t disp = target - label;
    if (disp < -128 || disp > 127) {
        const uint8_t opcode = *(label - 2);
        LOG(Caution, "FixupLabel rel8 overflow: label=%p target=%p disp=%lld "
                     "jump_opcode=0x%02X (74=JZ 75=JNZ EB=JMP) — caller emit "
                     "is too large to fit in a short jump\n",
            static_cast<void*>(label), static_cast<void*>(target),
            static_cast<long long>(disp), opcode);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    *(label - 1) = static_cast<uint8_t>(disp);
}

/* 32-bit Jcc rel32 (0F 8x cd) variants. Same patch protocol but
   with a 4-byte displacement. */
inline uint8_t* EmitJzLabel32 (uint8_t*& p) { Emit16(p, 0x840F); Emit32(p, 0); return p; }
inline uint8_t* EmitJnzLabel32(uint8_t*& p) { Emit16(p, 0x850F); Emit32(p, 0); return p; }
inline uint8_t* EmitJcLabel32 (uint8_t*& p) { Emit16(p, 0x820F); Emit32(p, 0); return p; }
inline uint8_t* EmitJncLabel32(uint8_t*& p) { Emit16(p, 0x830F); Emit32(p, 0); return p; }
inline uint8_t* EmitJnsLabel32(uint8_t*& p) { Emit16(p, 0x890F); Emit32(p, 0); return p; }
inline uint8_t* EmitJsLabel32 (uint8_t*& p) { Emit16(p, 0x880F); Emit32(p, 0); return p; }
inline uint8_t* EmitJoLabel32 (uint8_t*& p) { Emit16(p, 0x800F); Emit32(p, 0); return p; }
inline uint8_t* EmitJnoLabel32(uint8_t*& p) { Emit16(p, 0x810F); Emit32(p, 0); return p; }
inline uint8_t* EmitJlLabel32 (uint8_t*& p) { Emit16(p, 0x8C0F); Emit32(p, 0); return p; }
inline uint8_t* EmitJgeLabel32(uint8_t*& p) { Emit16(p, 0x8D0F); Emit32(p, 0); return p; }
inline uint8_t* EmitJleLabel32(uint8_t*& p) { Emit16(p, 0x8E0F); Emit32(p, 0); return p; }
inline uint8_t* EmitJgLabel32 (uint8_t*& p) { Emit16(p, 0x8F0F); Emit32(p, 0); return p; }
inline uint8_t* EmitJbeLabel32(uint8_t*& p) { Emit16(p, 0x860F); Emit32(p, 0); return p; }
inline uint8_t* EmitJaeLabel32(uint8_t*& p) { Emit16(p, 0x830F); Emit32(p, 0); return p; }
inline uint8_t* EmitJaLabel32 (uint8_t*& p) { Emit16(p, 0x870F); Emit32(p, 0); return p; }
inline uint8_t* EmitJbLabel32 (uint8_t*& p) { return EmitJcLabel32(p); }  /* JB and JC encode identically. */
inline uint8_t* EmitJmpLabel32(uint8_t*& p) { Emit8 (p, 0xE9);   Emit32(p, 0); return p; }

inline void FixupLabel32(uint8_t* label, uint8_t* target) {
    const uint32_t rel = static_cast<uint32_t>(target - label);
    std::memcpy(label - 4, &rel, 4);
}

/* Backward conditional-jump emit — opposite shape from EmitJzLabel
   family above. Each takes an absolute target captured earlier in
   the same emit stream and writes the matching Jcc rel32 directly,
   computing the displacement from (cursor + 6) to the target. */
inline void EmitJzBack(uint8_t*& p, uint8_t* target) {
    Emit8(p, 0x0F); Emit8(p, 0x84);
    const int32_t rel = static_cast<int32_t>(target - (p + 4));
    Emit32(p, static_cast<uint32_t>(rel));
}
inline void EmitJnzBack(uint8_t*& p, uint8_t* target) {
    Emit8(p, 0x0F); Emit8(p, 0x85);
    const int32_t rel = static_cast<int32_t>(target - (p + 4));
    Emit32(p, static_cast<uint32_t>(rel));
}

inline void EmitJmpReg(uint8_t*& p, uint8_t reg) {
    Emit8(p, 0xFF); EmitModRmReg(p, 3, reg, 4);
}

/* Stack moves. */
inline void EmitPushDwordPtr(uint8_t*& p, const void* ptr) {
    Emit8(p, 0xFF); EmitModRmReg(p, 0, 5, 6); EmitPtr(p, ptr);
}

/* MOV DWORD PTR [disp32], imm32 — Intel SDM: C7 /0 id (mod=00, r/m=101). */
inline void EmitMovDwordPtrImm32(uint8_t*& p, const void* ptr, uint32_t imm) {
    Emit8(p, 0xC7); EmitModRmReg(p, 0, 5, 0); EmitPtr(p, ptr); Emit32(p, imm);
}
inline void EmitPushReg(uint8_t*& p, uint8_t reg) { Emit8(p, static_cast<uint8_t>(0x50 + reg)); }
inline void EmitPush32(uint8_t*& p, uint32_t imm) { Emit8(p, 0x68); Emit32(p, imm); }
inline void EmitPushPtr(uint8_t*& p, const void* ptr) { Emit8(p, 0x68); EmitPtr(p, ptr); }
inline void EmitPopReg(uint8_t*& p, uint8_t reg) { Emit8(p, static_cast<uint8_t>(0x58 + reg)); }
inline void EmitPopM32(uint8_t*& p, const void* ptr) {
    Emit8(p, 0x8F); EmitModRmReg(p, 0, 5, 0); EmitPtr(p, ptr);
}

/* SETC r8 (0F 92 /0). */
inline void EmitSetcReg8(uint8_t*& p, uint8_t reg) {
    Emit16(p, 0x920F); EmitModRmReg(p, 3, reg, 0);
}

/* Arithmetic register/register. */
inline void EmitAddReg32Reg32(uint8_t*& p, uint8_t d, uint8_t s) { Emit8(p, 0x01); EmitModRmReg(p, 3, d, s); }
inline void EmitSubReg32Reg32(uint8_t*& p, uint8_t d, uint8_t s) { Emit8(p, 0x29); EmitModRmReg(p, 3, d, s); }
inline void EmitOrReg32Reg32 (uint8_t*& p, uint8_t d, uint8_t s) { Emit8(p, 0x09); EmitModRmReg(p, 3, d, s); }

inline void EmitIncReg(uint8_t*& p, uint8_t reg) { Emit8(p, static_cast<uint8_t>(reg + 0x40)); }
inline void EmitDecReg(uint8_t*& p, uint8_t reg) { Emit8(p, static_cast<uint8_t>(reg + 0x48)); }

/* ADD r32, imm32 — picks the shortest encoding: nothing for 0, INC
   for 1, 83 /0 ib for [-128,127], 05 id for EAX, 81 /0 id otherwise. */
inline void EmitAddRegImm32(uint8_t*& p, uint8_t reg, uint32_t unsigned_imm) {
    const int32_t imm = static_cast<int32_t>(unsigned_imm);
    if (imm == 0) return;
    if (imm == 1) { EmitIncReg(p, reg); return; }
    if (imm >= -128 && imm <= 127) {
        Emit8(p, 0x83); EmitModRmReg(p, 3, reg, 0); Emit8(p, static_cast<uint8_t>(imm));
        return;
    }
    if (reg == kEax) { Emit8(p, 0x05); Emit32(p, static_cast<uint32_t>(imm)); return; }
    Emit8(p, 0x81); EmitModRmReg(p, 3, reg, 0); Emit32(p, static_cast<uint32_t>(imm));
}

/* SUB r32, imm32 — mirror of EmitAddRegImm32. */
inline void EmitSubRegImm32(uint8_t*& p, uint8_t reg, uint32_t unsigned_imm) {
    const int32_t imm = static_cast<int32_t>(unsigned_imm);
    if (imm == 0) return;
    if (imm == 1) { EmitDecReg(p, reg); return; }
    if (imm >= -128 && imm <= 127) {
        Emit8(p, 0x83); EmitModRmReg(p, 3, reg, 5); Emit8(p, static_cast<uint8_t>(imm));
        return;
    }
    if (reg == kEax) { Emit8(p, 0x2D); Emit32(p, static_cast<uint32_t>(imm)); return; }
    Emit8(p, 0x81); EmitModRmReg(p, 3, reg, 5); Emit32(p, static_cast<uint32_t>(imm));
}

/* ADD/SUB/ADC r32, [disp32]. */
inline void EmitAddRegDwordPtr(uint8_t*& p, uint8_t reg, const void* ptr) {
    Emit8(p, 0x03); EmitModRmReg(p, 0, 5, reg); EmitPtr(p, ptr);
}
inline void EmitAddDwordPtrReg(uint8_t*& p, const void* ptr, uint8_t reg) {
    Emit8(p, 0x01); EmitModRmReg(p, 0, 5, reg); EmitPtr(p, ptr);
}
inline void EmitAdcDwordPtrReg(uint8_t*& p, const void* ptr, uint8_t reg) {
    Emit8(p, 0x11); EmitModRmReg(p, 0, 5, reg); EmitPtr(p, ptr);
}
inline void EmitSubRegDwordPtr(uint8_t*& p, uint8_t reg, const void* ptr) {
    Emit8(p, 0x2B); EmitModRmReg(p, 0, 5, reg); EmitPtr(p, ptr);
}

inline void EmitAndRegImm32(uint8_t*& p, uint8_t reg, uint32_t unsigned_imm) {
    const int32_t imm = static_cast<int32_t>(unsigned_imm);
    if (imm >= -128 && imm < 128) {
        Emit8(p, 0x83); EmitModRmReg(p, 3, reg, 4); Emit8(p, static_cast<uint8_t>(imm));
        return;
    }
    if (reg == kEax) { Emit8(p, 0x25); Emit32(p, static_cast<uint32_t>(imm)); return; }
    Emit8(p, 0x81); EmitModRmReg(p, 3, reg, 4); Emit32(p, static_cast<uint32_t>(imm));
}

inline void EmitCmpRegImm32(uint8_t*& p, uint8_t reg, uint32_t unsigned_imm) {
    const int32_t imm = static_cast<int32_t>(unsigned_imm);
    if (imm >= -128 && imm < 128) {
        Emit8(p, 0x83); EmitModRmReg(p, 3, reg, 7); Emit8(p, static_cast<uint8_t>(imm));
        return;
    }
    if (reg == kEax) { Emit8(p, 0x3D); Emit32(p, static_cast<uint32_t>(imm)); return; }
    Emit8(p, 0x81); EmitModRmReg(p, 3, reg, 7); Emit32(p, static_cast<uint32_t>(imm));
}

inline void EmitCmpRegDwordPtr(uint8_t*& p, uint8_t reg, const void* ptr) {
    Emit8(p, 0x3B); EmitModRmReg(p, 0, 5, reg); EmitPtr(p, ptr);
}
inline void EmitCmpRegReg(uint8_t*& p, uint8_t r1, uint8_t r2) {
    Emit8(p, 0x3B); EmitModRmReg(p, 3, r2, r1);
}
inline void EmitTestRegReg(uint8_t*& p, uint8_t r1, uint8_t r2) {
    Emit8(p, 0x85); EmitModRmReg(p, 3, r1, r2);
}
inline void EmitTestRegImm32(uint8_t*& p, uint8_t reg, uint32_t imm) {
    if (reg == kEax) { Emit8(p, 0xA9); Emit32(p, imm); }
    else             { Emit8(p, 0xF7); EmitModRmReg(p, 3, reg, 0); Emit32(p, imm); }
}

inline void EmitOrBytePtrImm8(uint8_t*& p, const void* ptr, uint8_t imm) {
    Emit8(p, 0x80); EmitModRmReg(p, 0, 5, 1); EmitPtr(p, ptr); Emit8(p, imm);
}

inline void EmitShlReg32Imm(uint8_t*& p, uint8_t reg, uint8_t imm) {
    Emit8(p, 0xC1); EmitModRmReg(p, 3, reg, 4); Emit8(p, imm);
}
inline void EmitShrReg32Imm(uint8_t*& p, uint8_t reg, uint8_t imm) {
    Emit8(p, 0xC1); EmitModRmReg(p, 3, reg, 5); Emit8(p, imm);
}

inline void EmitCwde(uint8_t*& p) { Emit8(p, 0x98); }

/* IMUL r32 — one-operand signed multiply producing EDX:EAX. */
inline void EmitImulReg32(uint8_t*& p, uint8_t reg) {
    Emit8(p, 0xF7); EmitModRmReg(p, 3, reg, 5);
}

/* BT [disp32], imm8 — sets x86 CF to bit imm8 of the dword at ptr. */
inline void EmitBtDwordPtrImm(uint8_t*& p, const void* ptr, uint8_t imm) {
    Emit16(p, 0xBA0F); EmitModRmReg(p, 0, 5, 4); EmitPtr(p, ptr); Emit8(p, imm);
}

constexpr uint8_t kStateReg = kEsi;
constexpr uint8_t kMmuReg   = kEbx;

/* MOV r32, [base + disp32] — 8B /r mod=10. */
inline void EmitMovRegBaseDisp32(uint8_t*& p, uint8_t dst, uint8_t base, int32_t disp) {
    Emit8(p, 0x8B); EmitModRmReg(p, 2, base, dst);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* LEA r32, [base + disp32] — 8D /r mod=10. Computes the effective
   address (no memory access) into dst. Used to materialize a
   per-instance ArmMmuState field pointer (e.g. data_tlb) into a
   scratch register for passing as a cdecl function-call argument. */
inline void EmitLeaRegBaseDisp32(uint8_t*& p, uint8_t dst, uint8_t base, int32_t disp) {
    Emit8(p, 0x8D); EmitModRmReg(p, 2, base, dst);
    Emit32(p, static_cast<uint32_t>(disp));
}

inline void EmitXchgRegBaseDisp32(uint8_t*& p, uint8_t reg, uint8_t base, int32_t disp) {
    Emit8(p, 0x87); EmitModRmReg(p, 2, base, reg);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* MOV [base + disp32], r32 — 89 /r mod=10. */
inline void EmitMovBaseDisp32Reg(uint8_t*& p, uint8_t base, int32_t disp, uint8_t src) {
    Emit8(p, 0x89); EmitModRmReg(p, 2, base, src);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* MOV [base + disp32], imm32 — C7 /0 mod=10. */
inline void EmitMovBaseDisp32Imm32(uint8_t*& p, uint8_t base, int32_t disp, uint32_t imm) {
    Emit8(p, 0xC7); EmitModRmReg(p, 2, base, 0);
    Emit32(p, static_cast<uint32_t>(disp));
    Emit32(p, imm);
}

/* MOV r8, [base + disp32] — 8A /r mod=10. */
inline void EmitMovByteRegBaseDisp32(uint8_t*& p, uint8_t dst, uint8_t base, int32_t disp) {
    Emit8(p, 0x8A); EmitModRmReg(p, 2, base, dst);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* MOV [base + disp32], r8 — 88 /r mod=10. */
inline void EmitMovBaseDisp32Byte(uint8_t*& p, uint8_t base, int32_t disp, uint8_t src) {
    Emit8(p, 0x88); EmitModRmReg(p, 2, base, src);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* MOVSX r32, byte [base + disp32] — 0F BE /r mod=10. Sign-extends the
   addressed byte into the full 32-bit dst. */
inline void EmitMovsxByteRegBaseDisp32(uint8_t*& p, uint8_t dst, uint8_t base, int32_t disp) {
    Emit8(p, 0x0F); Emit8(p, 0xBE); EmitModRmReg(p, 2, base, dst);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* CMP r8, byte [base + disp32] — 3A /r mod=10. */
inline void EmitCmpReg8BaseDisp32(uint8_t*& p, uint8_t reg8, uint8_t base, int32_t disp) {
    Emit8(p, 0x3A); EmitModRmReg(p, 2, base, reg8);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* BT [base], index — 0F A3 /r mod=00. CF = bit `index` of the bit-string based
   at [base] (memory bit-base addressing, so index may exceed 32). base must not
   be EBP/ESP. */
inline void EmitBtMemReg(uint8_t*& p, uint8_t base, uint8_t index) {
    Emit16(p, 0xA30F); EmitModRmReg(p, 0, base, index);
}

/* BTS [base], index — 0F AB /r mod=00. Sets bit `index` of the bit-string based
   at [base]. base must not be EBP/ESP. */
inline void EmitBtsMemReg(uint8_t*& p, uint8_t base, uint8_t index) {
    Emit16(p, 0xAB0F); EmitModRmReg(p, 0, base, index);
}

/* ADD r32, [base + disp32] — 03 /r mod=10. */
inline void EmitAddRegBaseDisp32(uint8_t*& p, uint8_t dst, uint8_t base, int32_t disp) {
    Emit8(p, 0x03); EmitModRmReg(p, 2, base, dst);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* ADD [base + disp32], r32 — 01 /r mod=10. */
inline void EmitAddBaseDisp32Reg(uint8_t*& p, uint8_t base, int32_t disp, uint8_t src) {
    Emit8(p, 0x01); EmitModRmReg(p, 2, base, src);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* ADC [base + disp32], r32 — 11 /r mod=10. */
inline void EmitAdcBaseDisp32Reg(uint8_t*& p, uint8_t base, int32_t disp, uint8_t src) {
    Emit8(p, 0x11); EmitModRmReg(p, 2, base, src);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* ADD DWORD PTR [base + disp32], imm8 (sign-extended) — 83 /0 mod=10 ib. */
inline void EmitAddBaseDisp32Imm8(uint8_t*& p, uint8_t base, int32_t disp, uint8_t imm) {
    Emit8(p, 0x83); EmitModRmReg(p, 2, base, 0);
    Emit32(p, static_cast<uint32_t>(disp));
    Emit8(p, imm);
}

/* ADC DWORD PTR [base + disp32], imm8 (sign-extended) — 83 /2 mod=10 ib. */
inline void EmitAdcBaseDisp32Imm8(uint8_t*& p, uint8_t base, int32_t disp, uint8_t imm) {
    Emit8(p, 0x83); EmitModRmReg(p, 2, base, 2);
    Emit32(p, static_cast<uint32_t>(disp));
    Emit8(p, imm);
}

/* SUB r32, [base + disp32] — 2B /r mod=10. */
inline void EmitSubRegBaseDisp32(uint8_t*& p, uint8_t dst, uint8_t base, int32_t disp) {
    Emit8(p, 0x2B); EmitModRmReg(p, 2, base, dst);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* CMP r32, [base + disp32] — 3B /r mod=10. */
inline void EmitCmpRegBaseDisp32(uint8_t*& p, uint8_t dst, uint8_t base, int32_t disp) {
    Emit8(p, 0x3B); EmitModRmReg(p, 2, base, dst);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* OR [base + disp8], imm8 — 80 /1 mod=01. */
inline void EmitOrByteBaseDisp8Imm8(uint8_t*& p, uint8_t base, int8_t disp, uint8_t imm) {
    Emit8(p, 0x80); EmitModRmReg(p, 1, base, 1);
    Emit8(p, static_cast<uint8_t>(disp));
    Emit8(p, imm);
}

/* PUSH [base + disp32] — FF /6 mod=10. */
inline void EmitPushBaseDisp32(uint8_t*& p, uint8_t base, int32_t disp) {
    Emit8(p, 0xFF); EmitModRmReg(p, 2, base, 6);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* POP [base + disp32] — 8F /0 mod=10. */
inline void EmitPopBaseDisp32(uint8_t*& p, uint8_t base, int32_t disp) {
    Emit8(p, 0x8F); EmitModRmReg(p, 2, base, 0);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* BT [base + disp32], imm8 — 0F BA /4 mod=10. Sets x86 CF to bit
   imm8 of the dword at base+disp. */
inline void EmitBtBaseDisp32Imm(uint8_t*& p, uint8_t base, int32_t disp, uint8_t imm) {
    Emit16(p, 0xBA0F); EmitModRmReg(p, 2, base, 4);
    Emit32(p, static_cast<uint32_t>(disp));
    Emit8(p, imm);
}

/* TEST byte ptr [base + disp32], imm8 — F6 /0 mod=10 ib. */
inline void EmitTestByteBaseDisp32Imm8(uint8_t*& p, uint8_t base, int32_t disp, uint8_t imm) {
    Emit8(p, 0xF6); EmitModRmReg(p, 2, base, 0);
    Emit32(p, static_cast<uint32_t>(disp));
    Emit8(p, imm);
}

/* OR r32, [base + disp32] — 0B /r mod=10. */
inline void EmitOrRegBaseDisp32(uint8_t*& p, uint8_t dst, uint8_t base, int32_t disp) {
    Emit8(p, 0x0B); EmitModRmReg(p, 2, base, dst);
    Emit32(p, static_cast<uint32_t>(disp));
}

/* JMP [base + disp32] — FF /4 mod=10. */
inline void EmitJmpBaseDisp32(uint8_t*& p, uint8_t base, int32_t disp) {
    Emit8(p, 0xFF); EmitModRmReg(p, 2, base, 4);
    Emit32(p, static_cast<uint32_t>(disp));
}

inline void EmitMovAbsIndexedReg(uint8_t*& p, uint32_t base_addr, uint8_t index_reg, uint8_t src_reg) {
    Emit8(p, 0x89);
    EmitModRmReg(p, 0, 4, src_reg);
    EmitSib(p, 0, index_reg, 5);
    Emit32(p, base_addr);
}

/* INC byte ptr [disp32] — FE /0. */
inline void EmitIncBytePtrAbs(uint8_t*& p, const void* ptr) {
    Emit8(p, 0xFE); EmitModRmReg(p, 0, 5, 0); EmitPtr(p, ptr);
}

/* MOVZX r32, byte ptr [disp32] — 0F B6 /r mod=00 r/m=5. */
inline void EmitMovzxRegBytePtrAbs(uint8_t*& p, uint8_t dst, const void* ptr) {
    Emit16(p, 0xB60F); EmitModRmReg(p, 0, 5, dst); EmitPtr(p, ptr);
}

/* ADD DWORD PTR [disp32], imm8 — 83 /0 mod=00 r/m=5 disp32 ib.
   Sign-extends imm8 to 32 bits before adding. Used for incrementing
   the absolute IO-pending-address slot between paired IO transfers
   (LDRD / STRD double-word IO emit). */
inline void EmitAddDwordPtrImm8(uint8_t*& p, const void* ptr, int8_t imm) {
    Emit8(p, 0x83); EmitModRmReg(p, 0, 5, 0); EmitPtr(p, ptr);
    Emit8(p, static_cast<uint8_t>(imm));
}

}  // namespace x86
