#pragma once

#include <cstdint>

#include "../core/service.h"

/* VABS / VNEG (A8.8.280 / A8.8.355). */
class ArmNeon2RegUnaryArith : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kAbs = 0u;
    static constexpr uint32_t kNeg = 1u;

    void HandleUnaryArith(uint32_t op_sel, uint32_t F, uint32_t esize,
                          uint32_t d_idx, uint32_t m_idx, uint32_t regs);

    static void __cdecl HandleUnaryArithHelper(ArmNeon2RegUnaryArith* svc,
                                               uint32_t op_sel, uint32_t F,
                                               uint32_t esize, uint32_t d_idx,
                                               uint32_t m_idx, uint32_t regs);
};
