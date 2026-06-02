#pragma once

#include <cstdint>

#include "../core/service.h"

/* VRECPE / VRSQRTE (A8.8.384 / A8.8.391). */
class ArmNeon2RegReciprocal : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kRecpe  = 0u;
    static constexpr uint32_t kRsqrte = 1u;

    void HandleReciprocal(uint32_t op_sel, uint32_t F,
                          uint32_t d_idx, uint32_t m_idx, uint32_t regs);

    static void __cdecl HandleReciprocalHelper(ArmNeon2RegReciprocal* svc,
                                               uint32_t op_sel, uint32_t F,
                                               uint32_t d_idx, uint32_t m_idx,
                                               uint32_t regs);
};
