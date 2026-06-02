#pragma once

#include <cstdint>

#include "../core/service.h"

/* 2-reg-shift immediate NEON ops (A7.4.4). Distinct encoding region
   (bit23=1) and shift-amount derivation from L:imm6. */
class ArmNeonShiftImm : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kSiShrS  = 0u;  /* VSHR  signed   (arith)              */
    static constexpr uint32_t kSiShrU  = 1u;  /* VSHR  unsigned (logical)            */
    static constexpr uint32_t kSiShl   = 2u;  /* VSHL imm (no signedness)            */
    static constexpr uint32_t kSiRshrS = 3u;  /* VRSHR signed   (rounding arith)     */
    static constexpr uint32_t kSiRshrU = 4u;  /* VRSHR unsigned (rounding logical)   */
    /* VSRA / VRSRA: d = d + (a >> shift) [+ rounding] (A8.8.402 / A8.8.393). */
    static constexpr uint32_t kSiSraS  = 5u;  /* VSRA  signed   accumulate (arith)   */
    static constexpr uint32_t kSiSraU  = 6u;  /* VSRA  unsigned accumulate (logical) */
    static constexpr uint32_t kSiRsraS = 7u;  /* VRSRA signed   rounding accumulate  */
    static constexpr uint32_t kSiRsraU = 8u;  /* VRSRA unsigned rounding accumulate  */
    /* VSRI / VSLI: insert shifted m into d, preserving d's bits outside
       the shift mask. No signed/unsigned distinction (A8.8.403 / A8.8.400). */
    static constexpr uint32_t kSiSri   = 9u;  /* VSRI shift-right-and-insert         */
    static constexpr uint32_t kSiSli   = 10u; /* VSLI shift-left-and-insert          */
    /* VSHRN (A8.8.399) / VRSHRN (A8.8.390): narrowing right shift — reads
       a Q register (2*esize-bit elements), writes a D register (esize-bit
       elements). VRSHRN adds the rounding (val>>rs)+rbit idiom. */
    static constexpr uint32_t kSiShrn  = 11u; /* VSHRN  truncating narrowing right   */
    static constexpr uint32_t kSiRshrn = 12u; /* VRSHRN rounding   narrowing right   */
    /* VSHLL (A8.8.397 T1/A1): widening left shift — reads a D register
       (esize-bit elements), writes a Q register (2*esize-bit elements).
       U bit selects sign-extend vs zero-extend before the shift. */
    static constexpr uint32_t kSiShllS = 13u; /* VSHLL signed   widening left        */
    static constexpr uint32_t kSiShllU = 14u; /* VSHLL unsigned widening left        */

    /* Right-shift ops use shift_amount in [1, esize]; VSHL imm uses [0, esize-1].
       esize in {8,16,32,64}; regs=1 (Q=0) or 2 (Q=1). */
    void HandleShiftImm(uint32_t op, uint32_t d_idx, uint32_t m_idx,
                        uint32_t esize, uint32_t shift_amount, uint32_t regs);

    static void __cdecl HandleShiftImmHelper(ArmNeonShiftImm* svc, uint32_t op,
                                             uint32_t d_idx, uint32_t m_idx,
                                             uint32_t esize, uint32_t shift_amount,
                                             uint32_t regs);

    /* Narrowing: src is a Q register at m_idx..m_idx+1 (m_idx must be even),
       dst is one D register at d_idx, esize is the OUTPUT element size. */
    void HandleShiftImmNarrow(uint32_t op, uint32_t d_idx, uint32_t m_idx,
                              uint32_t esize, uint32_t shift_amount);

    static void __cdecl HandleShiftImmNarrowHelper(ArmNeonShiftImm* svc, uint32_t op,
                                                   uint32_t d_idx, uint32_t m_idx,
                                                   uint32_t esize, uint32_t shift_amount);

    /* Widening: src is one D register at m_idx, dst is a Q register at
       d_idx..d_idx+1 (d_idx must be even), esize is the INPUT element size.
       shift_amount in [0, esize-1] (T1/A1). */
    void HandleShiftImmWiden(uint32_t op, uint32_t d_idx, uint32_t m_idx,
                             uint32_t esize, uint32_t shift_amount);

    static void __cdecl HandleShiftImmWidenHelper(ArmNeonShiftImm* svc, uint32_t op,
                                                  uint32_t d_idx, uint32_t m_idx,
                                                  uint32_t esize, uint32_t shift_amount);
};
