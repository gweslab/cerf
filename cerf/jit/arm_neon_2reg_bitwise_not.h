#pragma once

#include <cstdint>

#include "../core/service.h"

/* VMVN (register) — A8.8.354. Whole-D-register bitwise NOT. */
class ArmNeon2RegBitwiseNot : public Service {
public:
    using Service::Service;

    void HandleMvn(uint32_t d_idx, uint32_t m_idx, uint32_t regs);

    static void __cdecl HandleMvnHelper(ArmNeon2RegBitwiseNot* svc,
                                        uint32_t d_idx, uint32_t m_idx,
                                        uint32_t regs);
};
