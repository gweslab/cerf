#pragma once

#include <cstdint>

#include "../core/service.h"

/* VACGE / VACGT — A8.8.281, opc=1110 C=1 U=1. Absolute-value compares;
   bit[21] selects ACGE (0) / ACGT (1). VACLE / VACLT are assembler
   pseudo-instructions for swapped-operand VACGE / VACGT and encode as
   the same instruction. */
class ArmNeon3SameFpAbsCompare : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kAcge = 0u;
    static constexpr uint32_t kAcgt = 1u;

    void Handle3SameFpAbsCompare(uint32_t op_sel, uint32_t d_idx,
                                 uint32_t n_idx, uint32_t m_idx,
                                 uint32_t regs);

    static void __cdecl Handle3SameFpAbsCompareHelper(
            ArmNeon3SameFpAbsCompare* svc,
            uint32_t                  op_sel,
            uint32_t                  d_idx,
            uint32_t                  n_idx,
            uint32_t                  m_idx,
            uint32_t                  regs);
};
