#pragma once

#include <cstdint>

#include "../core/service.h"

/* VMLA.F32 / VMLS.F32 — A7.4.1 opc=1101 B=1 U=0 (A8.8.337). */
class ArmNeon3SameFpMulAcc : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kMla = 0u;
    static constexpr uint32_t kMls = 1u;

    void Handle3SameFpMulAcc(uint32_t op_sel, uint32_t d_idx, uint32_t n_idx,
                             uint32_t m_idx, uint32_t regs);

    static void __cdecl Handle3SameFpMulAccHelper(ArmNeon3SameFpMulAcc* svc,
                                                  uint32_t op_sel,
                                                  uint32_t d_idx,
                                                  uint32_t n_idx,
                                                  uint32_t m_idx,
                                                  uint32_t regs);
};
