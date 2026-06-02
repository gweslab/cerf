#pragma once

#include <cstdint>

#include "../core/service.h"

/* VPMAX / VPMIN (floating-point) — A8.8.366, opc=1111 C=0 U=1. */
class ArmNeon3SameFpPairMinMax : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kMax = 0u;
    static constexpr uint32_t kMin = 1u;

    void Handle3SameFpPairMinMax(uint32_t op_sel, uint32_t d_idx,
                                 uint32_t n_idx, uint32_t m_idx);

    static void __cdecl Handle3SameFpPairMinMaxHelper(
            ArmNeon3SameFpPairMinMax* svc,
            uint32_t                  op_sel,
            uint32_t                  d_idx,
            uint32_t                  n_idx,
            uint32_t                  m_idx);
};
