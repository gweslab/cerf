#pragma once

#include <cstdint>

#include "../core/service.h"

/* VSWP (A8.8.418). */
class ArmNeon2RegSwap : public Service {
public:
    using Service::Service;

    void HandleSwap(uint32_t d_idx, uint32_t m_idx, uint32_t regs);

    static void __cdecl HandleSwapHelper(ArmNeon2RegSwap* svc,
                                         uint32_t d_idx, uint32_t m_idx,
                                         uint32_t regs);
};
