#pragma once

#include <cstdint>

#include "../core/service.h"

/* VQABS / VQNEG (A8.8.369 / A8.8.375). */
class ArmNeon2RegSatAbsNeg : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kQabs = 0u;
    static constexpr uint32_t kQneg = 1u;

    void HandleSatAbsNeg(uint32_t op_sel, uint32_t esize,
                         uint32_t d_idx, uint32_t m_idx, uint32_t regs);

    static void __cdecl HandleSatAbsNegHelper(ArmNeon2RegSatAbsNeg* svc,
                                              uint32_t op_sel, uint32_t esize,
                                              uint32_t d_idx, uint32_t m_idx,
                                              uint32_t regs);
};
