#pragma once

#include <cstdint>

#include "../core/service.h"

/* Two-registers-and-a-scalar NEON ops (A7.4.3). */
class ArmNeon2RegScalar : public Service {
public:
    using Service::Service;

    /* VMLAL/VMLSL by scalar (A8.8.338 T2/A2). Long: Qd[e] += op1[e]*scalar
       (or -=). U bit (passed as `u` arg) selects sign/zero extend before mul. */
    static constexpr uint32_t kS2sMlal = 2u;
    static constexpr uint32_t kS2sMlsl = 3u;

    /* VMULL by scalar (A8.8.352 T2/A2): Qd[e] = op1*scalar, U bit selects
       signedness. */
    static constexpr uint32_t kS2sMull = 5u;

    /* VQDMLAL/VQDMLSL by scalar (A8.8.371 T2/A2). Signed only (U=0 fixed).
       Saturating doubled product, signed-saturated accumulator, sticky
       FPSCR.QC. Sizes 01 / 10 only (esize 16 / 32). */
    static constexpr uint32_t kS2sVqdmlal = 6u;
    static constexpr uint32_t kS2sVqdmlsl = 7u;

    /* VQDMULL by scalar (A8.8.373 T2/A2). Signed only. Saturating doubled
       product, no accumulator: Qd[e] = SatQ(2*op1*scalar, 2*esize). */
    static constexpr uint32_t kS2sVqdmull = 8u;

    /* VQDMULH/VQRDMULH by scalar (A8.8.372/A8.8.376 T2/A2). Same-length:
       Dd[r][e] = SignedSatQ((2*op1*scalar [+round]) >> esize, esize).
       Only MIN*MIN saturates per A8.8.372 line 47921. */
    static constexpr uint32_t kS2sVqdmulh  = 9u;
    static constexpr uint32_t kS2sVqrdmulh = 10u;

    /* esize: INPUT element size 16 or 32 (place_fn UNDs others). Output
       is 2*esize. u=1 unsigned, u=0 signed. */
    void HandleScalarMlsMlaLong(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                                uint32_t m_idx, uint32_t esize, uint32_t index,
                                uint32_t u);

    static void __cdecl HandleScalarMlsMlaLongHelper(ArmNeon2RegScalar* svc,
                                                     uint32_t op,
                                                     uint32_t d_idx, uint32_t n_idx,
                                                     uint32_t m_idx, uint32_t esize,
                                                     uint32_t index, uint32_t u);

    /* esize: INPUT element size 16 or 32 (place_fn UNDs others). Output
       is 2*esize signed-saturated. Sets FPSCR.QC on saturation. */
    void HandleScalarMulLongSat(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                                uint32_t m_idx, uint32_t esize, uint32_t index);

    static void __cdecl HandleScalarMulLongSatHelper(ArmNeon2RegScalar* svc,
                                                     uint32_t op,
                                                     uint32_t d_idx, uint32_t n_idx,
                                                     uint32_t m_idx, uint32_t esize,
                                                     uint32_t index);

    /* Same-length saturating multiply returning high half. esize ∈ {16, 32};
       output esize bits per element. Sets FPSCR.QC if MIN*MIN saturates. */
    void HandleScalarMulhSat(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                             uint32_t m_idx, uint32_t esize, uint32_t index,
                             uint32_t regs);

    static void __cdecl HandleScalarMulhSatHelper(ArmNeon2RegScalar* svc,
                                                  uint32_t op,
                                                  uint32_t d_idx, uint32_t n_idx,
                                                  uint32_t m_idx, uint32_t esize,
                                                  uint32_t index, uint32_t regs);
};
