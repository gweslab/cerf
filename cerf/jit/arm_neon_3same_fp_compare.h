#pragma once

#include <cstdint>

#include "../core/service.h"

/* VCEQ.F32 / VCGE.F32 / VCGT.F32 (register form) — A7.4.1 opc=1110 C=0
   (A8.8.291 / A8.8.293 / A8.8.295). */
class ArmNeon3SameFpCompare : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kEq = 0u;
    static constexpr uint32_t kGe = 1u;
    static constexpr uint32_t kGt = 2u;

    void Handle3SameFpCompare(uint32_t op_sel, uint32_t d_idx, uint32_t n_idx,
                              uint32_t m_idx, uint32_t regs);

    static void __cdecl Handle3SameFpCompareHelper(ArmNeon3SameFpCompare* svc,
                                                   uint32_t op_sel,
                                                   uint32_t d_idx,
                                                   uint32_t n_idx,
                                                   uint32_t m_idx,
                                                   uint32_t regs);
};
