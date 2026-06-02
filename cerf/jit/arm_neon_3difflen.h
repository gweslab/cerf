#pragma once

#include <cstdint>

#include "../core/service.h"

/* 3-registers-of-different-lengths NEON ops (A7.4.2). */
class ArmNeon3DiffLen : public Service {
public:
    using Service::Service;

    /* Long/wide add and subtract (A8.8.285 / A8.8.417). Long: D op D -> Q.
       Wide: Q op D -> Q. */
    static constexpr uint32_t kDlAddLong = 0u;
    static constexpr uint32_t kDlAddWide = 1u;
    static constexpr uint32_t kDlSubLong = 2u;
    static constexpr uint32_t kDlSubWide = 3u;

    /* Add/Sub Narrow returning High Half (A8.8.284/416/383/394).
       Q op Q -> D; the R variants add round_const = 1<<(esize-1)
       before taking the high half. */
    static constexpr uint32_t kDlAddhn  = 4u;
    static constexpr uint32_t kDlSubhn  = 5u;
    static constexpr uint32_t kDlRaddhn = 6u;
    static constexpr uint32_t kDlRsubhn = 7u;

    /* Absolute-Difference Long family (A8.8.277 VABAL, A8.8.278 VABDL).
       D op D -> Q. VABAL accumulates: Qd += |Dn - Dm|. */
    static constexpr uint32_t kDlAbdlS = 8u;
    static constexpr uint32_t kDlAbdlU = 9u;
    static constexpr uint32_t kDlAbalS = 10u;
    static constexpr uint32_t kDlAbalU = 11u;

    /* Multiply-Long family (A8.8.336 VMLAL/VMLSL T2/A2, A8.8.350 VMULL T2/A2).
       D op D -> Q. VMLAL/VMLSL accumulate; VMULL int just multiplies;
       VMULL.P8 is carry-less GF(2) multiply (esize=8, U=0 enforced). */
    static constexpr uint32_t kDlMlalS    = 12u;
    static constexpr uint32_t kDlMlalU    = 13u;
    static constexpr uint32_t kDlMlslS    = 14u;
    static constexpr uint32_t kDlMlslU    = 15u;
    static constexpr uint32_t kDlMullIntS = 16u;
    static constexpr uint32_t kDlMullIntU = 17u;
    static constexpr uint32_t kDlMullPoly = 18u;

    /* Saturating Doubling Multiply Long family (A8.8.371 VQDMLAL/VQDMLSL,
       A8.8.373 VQDMULL). Signed only (U fixed 0). The product is doubled
       and signed-saturated to 2*esize bits; FPSCR.QC is set on saturation. */
    static constexpr uint32_t kDlVqdmlal = 19u;
    static constexpr uint32_t kDlVqdmlsl = 20u;
    static constexpr uint32_t kDlVqdmull = 21u;

    /* esize: INPUT (short) element size 8/16/32; output is 2*esize. */
    void HandleAddSubLW(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                        uint32_t m_idx, uint32_t esize, uint32_t u);

    static void __cdecl HandleAddSubLWHelper(ArmNeon3DiffLen* svc, uint32_t op,
                                             uint32_t d_idx, uint32_t n_idx,
                                             uint32_t m_idx, uint32_t esize,
                                             uint32_t u);

    /* esize: OUTPUT (short) element size 8/16/32; inputs are 2*esize. */
    void HandleAddSubHN(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                        uint32_t m_idx, uint32_t esize);

    static void __cdecl HandleAddSubHNHelper(ArmNeon3DiffLen* svc, uint32_t op,
                                             uint32_t d_idx, uint32_t n_idx,
                                             uint32_t m_idx, uint32_t esize);

    /* esize: INPUT (short) element size 8/16/32; output is 2*esize. */
    void HandleAbsDiffLong(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                           uint32_t m_idx, uint32_t esize);

    static void __cdecl HandleAbsDiffLongHelper(ArmNeon3DiffLen* svc, uint32_t op,
                                                uint32_t d_idx, uint32_t n_idx,
                                                uint32_t m_idx, uint32_t esize);

    /* esize: INPUT element size 8/16/32; output is 2*esize. For
       kDlMullPoly the place_fn enforces esize=8. */
    void HandleMulLong(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                       uint32_t m_idx, uint32_t esize);

    static void __cdecl HandleMulLongHelper(ArmNeon3DiffLen* svc, uint32_t op,
                                            uint32_t d_idx, uint32_t n_idx,
                                            uint32_t m_idx, uint32_t esize);

    /* esize: INPUT element size 16 or 32 (place_fn UNDs other sizes).
       Output is 2*esize, signed-saturated. Sets FPSCR.QC on saturation. */
    void HandleMulLongSat(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                          uint32_t m_idx, uint32_t esize);

    static void __cdecl HandleMulLongSatHelper(ArmNeon3DiffLen* svc, uint32_t op,
                                               uint32_t d_idx, uint32_t n_idx,
                                               uint32_t m_idx, uint32_t esize);
};
