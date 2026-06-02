#pragma once

#include <cstdint>

#include "../core/service.h"

/* VCLS / VCLZ / VCNT (A8.8.299 / A8.8.302 / A8.8.304): per-element bit
   counting ops. Each scans an esize-bit element and returns a count. */
class ArmNeon2RegBitcount : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kCls = 0u;
    static constexpr uint32_t kClz = 1u;
    static constexpr uint32_t kCnt = 2u;

    void HandleBitcount(uint32_t op, uint32_t d_idx, uint32_t m_idx,
                        uint32_t esize, uint32_t regs);

    static void __cdecl HandleBitcountHelper(ArmNeon2RegBitcount* svc, uint32_t op,
                                             uint32_t d_idx, uint32_t m_idx,
                                             uint32_t esize, uint32_t regs);
};
