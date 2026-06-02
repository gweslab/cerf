#pragma once

#include <cstdint>

#include "../core/service.h"

/* VADD.F32 / VSUB.F32 / VMUL.F32 / VABD.F32 — A7.4.1 opc=1101 family
   (A8.8.283 / A8.8.415 / A8.8.351 / A8.8.279). */
class ArmNeon3SameFpArith : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kAdd = 0u;
    static constexpr uint32_t kSub = 1u;
    static constexpr uint32_t kMul = 2u;
    static constexpr uint32_t kAbd = 3u;

    void Handle3SameFpArith(uint32_t op_sel, uint32_t d_idx, uint32_t n_idx,
                            uint32_t m_idx, uint32_t regs);

    static void __cdecl Handle3SameFpArithHelper(ArmNeon3SameFpArith* svc,
                                                 uint32_t op_sel,
                                                 uint32_t d_idx,
                                                 uint32_t n_idx,
                                                 uint32_t m_idx,
                                                 uint32_t regs);
};
