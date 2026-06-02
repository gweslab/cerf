#pragma once

#include <cstdint>

#include "../core/service.h"

/* VRECPS / VRSQRTS — A8.8.385 / A8.8.392, opc=1111 C=1 U=0. bit[21]
   selects: 0=VRECPS (2 - op1*op2), 1=VRSQRTS ((3 - op1*op2) / 2). */
class ArmNeon3SameFpRecipStep : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kRecps  = 0u;
    static constexpr uint32_t kRsqrts = 1u;

    void Handle3SameFpRecipStep(uint32_t op_sel, uint32_t d_idx,
                                uint32_t n_idx, uint32_t m_idx,
                                uint32_t regs);

    static void __cdecl Handle3SameFpRecipStepHelper(
            ArmNeon3SameFpRecipStep* svc,
            uint32_t                 op_sel,
            uint32_t                 d_idx,
            uint32_t                 n_idx,
            uint32_t                 m_idx,
            uint32_t                 regs);
};
