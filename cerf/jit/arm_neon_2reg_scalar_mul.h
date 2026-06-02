#pragma once

#include <cstdint>

#include "../core/service.h"

/* VMLA / VMLS / VMUL by scalar (A8.8.338 / A8.8.352, T1/A1). */
class ArmNeon2RegScalarMul : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kMla = 0u;
    static constexpr uint32_t kMls = 1u;
    static constexpr uint32_t kMul = 2u;

    void HandleScalarMul(uint32_t op_sel, uint32_t F, uint32_t esize,
                         uint32_t d_idx, uint32_t n_idx, uint32_t m_idx,
                         uint32_t index, uint32_t regs);

    static void __cdecl HandleScalarMulHelper(ArmNeon2RegScalarMul* svc,
                                              uint32_t op_sel, uint32_t F,
                                              uint32_t esize, uint32_t d_idx,
                                              uint32_t n_idx, uint32_t m_idx,
                                              uint32_t index, uint32_t regs);
};
