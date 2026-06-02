#pragma once

#include <cstdint>

#include "../core/service.h"

/* 3-registers-same-length integer / logical / per-element NEON ops
   (A7.4.1). */
class ArmNeonSimd3Same : public Service {
public:
    using Service::Service;

    /* Selector values are stable — referenced by decode + emit. */
    static constexpr uint32_t kS3Add = 0u;
    static constexpr uint32_t kS3Sub = 1u;
    static constexpr uint32_t kS3And = 2u;   /* VAND  a & b   */
    static constexpr uint32_t kS3Bic = 3u;   /* VBIC  a & ~b  */
    static constexpr uint32_t kS3Orr = 4u;   /* VORR  a | b   */
    static constexpr uint32_t kS3Orn = 5u;   /* VORN  a | ~b  */
    static constexpr uint32_t kS3Eor = 6u;   /* VEOR  a ^ b   */
    static constexpr uint32_t kS3Mul = 7u;   /* VMUL integer a * b (signedness don't-care, A8.8.350). */
    /* Compares (A8.8.291/421/295/293) -> per-element all-ones / all-zeros. */
    static constexpr uint32_t kS3Ceq  = 8u;
    static constexpr uint32_t kS3Tst  = 9u;
    static constexpr uint32_t kS3CgtS = 10u;
    static constexpr uint32_t kS3CgtU = 11u;
    static constexpr uint32_t kS3CgeS = 12u;
    static constexpr uint32_t kS3CgeU = 13u;
    /* VMAX/VMIN (A8.8.334). */
    static constexpr uint32_t kS3MaxS = 14u;
    static constexpr uint32_t kS3MaxU = 15u;
    static constexpr uint32_t kS3MinS = 16u;
    static constexpr uint32_t kS3MinU = 17u;
    /* Halving add/sub (A8.8.319) + rounding halving add (A8.8.387). */
    static constexpr uint32_t kS3HaddS  = 18u;
    static constexpr uint32_t kS3HaddU  = 19u;
    static constexpr uint32_t kS3HsubS  = 20u;
    static constexpr uint32_t kS3HsubU  = 21u;
    static constexpr uint32_t kS3RhaddS = 22u;
    static constexpr uint32_t kS3RhaddU = 23u;
    /* VABD (A8.8.278). */
    static constexpr uint32_t kS3AbdS = 24u;
    static constexpr uint32_t kS3AbdU = 25u;
    /* VSHL register (A8.8.396) — data=D[m], shift=signed low byte of D[n]. */
    static constexpr uint32_t kS3ShlS = 26u;
    static constexpr uint32_t kS3ShlU = 27u;
    /* VRSHL register (A8.8.388) — same operand reversal, rounding right shift. */
    static constexpr uint32_t kS3RshlS = 28u;
    static constexpr uint32_t kS3RshlU = 29u;
    /* VMUL.P8 polynomial (A8.8.350, op=1): carry-less multiply over GF(2).
       Place_fn enforces esize=8 (size != 00 is UNDEFINED per A8.8.350). */
    static constexpr uint32_t kS3MulP = 30u;
    /* VBSL/VBIT/VBIF (A8.8.290): bitwise selection under mask. The encoding's
       size field discriminates the op (01=BSL, 10=BIT, 11=BIF); ops are
       whole-register bitwise so the per-element loop with any esize yields
       the correct result. All three read D[d] as a third input. */
    static constexpr uint32_t kS3Bsl = 31u;
    static constexpr uint32_t kS3Bit = 32u;
    static constexpr uint32_t kS3Bif = 33u;

    void HandleSimd3Same(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                         uint32_t m_idx, uint32_t esize, uint32_t regs);

    static void __cdecl HandleSimd3SameHelper(ArmNeonSimd3Same* svc, uint32_t op,
                                              uint32_t d_idx, uint32_t n_idx,
                                              uint32_t m_idx, uint32_t esize,
                                              uint32_t regs);
};
