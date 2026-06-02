#pragma once

#include <cstdint>

#include "../core/service.h"

/* Saturating 3-reg-same NEON ops (A8.8.370/382): clamp each element to the
   esize-bit signed/unsigned range and set FPSCR.QC on any saturation. */
class ArmNeonSat : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kSatAddS  = 0u;  /* VQADD  signed              */
    static constexpr uint32_t kSatAddU  = 1u;  /* VQADD  unsigned            */
    static constexpr uint32_t kSatSubS  = 2u;  /* VQSUB  signed              */
    static constexpr uint32_t kSatSubU  = 3u;  /* VQSUB  unsigned            */
    /* VQSHL (register, A8.8.379) + VQRSHL (A8.8.377): saturating left
       shift; right shift is truncating (VQSHL) or rounding (VQRSHL).
       No saturation on right shift — the result always fits in esize. */
    static constexpr uint32_t kSatShlS  = 4u;  /* VQSHL  signed              */
    static constexpr uint32_t kSatShlU  = 5u;  /* VQSHL  unsigned            */
    static constexpr uint32_t kSatRshlS = 6u;  /* VQRSHL signed (rounding)   */
    static constexpr uint32_t kSatRshlU = 7u;  /* VQRSHL unsigned (rounding) */
    /* VQSHL/VQSHLU immediate (A8.8.380). VQSHLU is signed-in, unsigned-out:
       negative saturates to 0 (then unsigned upper clamp). */
    static constexpr uint32_t kSatShlImmS  = 8u;  /* VQSHL.S imm signed-in / signed-out */
    static constexpr uint32_t kSatShlImmU  = 9u;  /* VQSHL.U imm unsigned-in / unsigned-out */
    static constexpr uint32_t kSatShlImmSU = 10u; /* VQSHLU imm signed-in / unsigned-out */
    /* Saturating narrowing right shift: source is 2*esize, output esize.
       A8.8.381 VQSHRN/VQSHRUN (truncating), A8.8.378 VQRSHRN/VQRSHRUN (rounding). */
    static constexpr uint32_t kSatShrnS   = 11u; /* VQSHRN   signed-in / signed-out      */
    static constexpr uint32_t kSatShrnU   = 12u; /* VQSHRN   unsigned-in / unsigned-out  */
    static constexpr uint32_t kSatShrnSU  = 13u; /* VQSHRUN  signed-in / unsigned-out    */
    static constexpr uint32_t kSatRShrnS  = 14u; /* VQRSHRN  signed-in / signed-out      */
    static constexpr uint32_t kSatRShrnU  = 15u; /* VQRSHRN  unsigned-in / unsigned-out  */
    static constexpr uint32_t kSatRShrnSU = 16u; /* VQRSHRUN signed-in / unsigned-out    */

    void HandleSimd3SameSat(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                            uint32_t m_idx, uint32_t esize, uint32_t regs);

    static void __cdecl HandleSimd3SameSatHelper(ArmNeonSat* sat, uint32_t op,
                                                 uint32_t d_idx, uint32_t n_idx,
                                                 uint32_t m_idx, uint32_t esize,
                                                 uint32_t regs);

    /* shift_amount in [0, esize-1] (left shift); regs=1|2 per Q. */
    void HandleShiftImmSat(uint32_t op, uint32_t d_idx, uint32_t m_idx,
                           uint32_t esize, uint32_t shift_amount, uint32_t regs);

    static void __cdecl HandleShiftImmSatHelper(ArmNeonSat* sat, uint32_t op,
                                                uint32_t d_idx, uint32_t m_idx,
                                                uint32_t esize, uint32_t shift_amount,
                                                uint32_t regs);

    /* Saturating narrowing right shift. Source is a Q register (2*esize-bit
       elements); dst is one D register (esize-bit). shift_amount ∈ [1, esize_out]. */
    void HandleShiftImmNarrowSat(uint32_t op, uint32_t d_idx, uint32_t m_idx,
                                 uint32_t esize, uint32_t shift_amount);

    static void __cdecl HandleShiftImmNarrowSatHelper(ArmNeonSat* sat, uint32_t op,
                                                      uint32_t d_idx, uint32_t m_idx,
                                                      uint32_t esize, uint32_t shift_amount);

private:
    /* Saturating left-shift helpers shared by VQSHL/VQRSHL. shift>=0;
       on saturation, sets `saturated` (caller OR-accumulates into the
       per-element loop flag). */
    static uint64_t SatLeftShiftU(uint64_t value, int32_t shift,
                                  uint32_t esize, bool& saturated);
    static uint64_t SatLeftShiftS(int64_t value, int32_t shift,
                                  uint32_t esize, bool& saturated);
};
