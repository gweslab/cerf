#pragma once

#include <cstdint>

#include "../core/service.h"

/* VCVT int↔fp Advanced SIMD (A8.8.305). Selectors match the encoding's
   2-bit op field at bits[8:7]: op[1]=to_integer, op[0]=unsigned. */
class ArmNeon2RegCvtIntFp : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kIntSToFp = 0u;  /* op=00 — .F32.S32 (int s→fp) */
    static constexpr uint32_t kIntUToFp = 1u;  /* op=01 — .F32.U32 (int u→fp) */
    static constexpr uint32_t kFpToIntS = 2u;  /* op=10 — .S32.F32 (fp→int s) */
    static constexpr uint32_t kFpToIntU = 3u;  /* op=11 — .U32.F32 (fp→int u) */

    void HandleCvtIntFp(uint32_t op_sel, uint32_t d_idx, uint32_t m_idx,
                        uint32_t regs);

    static void __cdecl HandleCvtIntFpHelper(ArmNeon2RegCvtIntFp* svc,
                                             uint32_t op_sel, uint32_t d_idx,
                                             uint32_t m_idx, uint32_t regs);
};
