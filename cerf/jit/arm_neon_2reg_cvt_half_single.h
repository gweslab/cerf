#pragma once

#include <cstdint>

#include "../core/service.h"

/* VCVT half↔single Advanced SIMD (A8.8.310). */
class ArmNeon2RegCvtHalfSingle : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kSingleToHalf = 0u;  /* op=0 — .F16.F32 */
    static constexpr uint32_t kHalfToSingle = 1u;  /* op=1 — .F32.F16 */

    void HandleCvtHalfSingle(uint32_t op_sel, uint32_t d_idx, uint32_t m_idx);

    static void __cdecl HandleCvtHalfSingleHelper(ArmNeon2RegCvtHalfSingle* svc,
                                                  uint32_t op_sel,
                                                  uint32_t d_idx,
                                                  uint32_t m_idx);
};
