#pragma once

#include <cstdint>

#include "../core/service.h"

/* VMOVN / VQMOVUN / VQMOVN.S / VQMOVN.U (A8.8.347 / A8.8.374). Selectors
   match the encoding's 2-bit `op` field at bits[7:6]. */
class ArmNeon2RegNarrow : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kMovn   = 0u;  /* op=00 — no saturation */
    static constexpr uint32_t kQmovun = 1u;  /* op=01 — signed→unsigned sat */
    static constexpr uint32_t kQmovnS = 2u;  /* op=10 — signed→signed sat */
    static constexpr uint32_t kQmovnU = 3u;  /* op=11 — unsigned→unsigned sat */

    void HandleNarrow(uint32_t op_sel, uint32_t esize_out,
                      uint32_t d_idx, uint32_t m_idx);

    static void __cdecl HandleNarrowHelper(ArmNeon2RegNarrow* svc,
                                           uint32_t op_sel, uint32_t esize_out,
                                           uint32_t d_idx, uint32_t m_idx);
};
