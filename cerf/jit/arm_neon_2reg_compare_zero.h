#pragma once

#include <cstdint>

#include "../core/service.h"

/* VCEQ / VCGT / VCGE / VCLE / VCLT immediate #0
   (A8.8.292 / A8.8.296 / A8.8.294 / A8.8.298 / A8.8.301). */
class ArmNeon2RegCompareZero : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kCgt = 0u;  /* bits[9:7] = 000 */
    static constexpr uint32_t kCge = 1u;  /* bits[9:7] = 001 */
    static constexpr uint32_t kCeq = 2u;  /* bits[9:7] = 010 */
    static constexpr uint32_t kCle = 3u;  /* bits[9:7] = 011 */
    static constexpr uint32_t kClt = 4u;  /* bits[9:7] = 100 */

    void HandleCompareZero(uint32_t op_sel, uint32_t F, uint32_t esize,
                           uint32_t d_idx, uint32_t m_idx, uint32_t regs);

    static void __cdecl HandleCompareZeroHelper(ArmNeon2RegCompareZero* svc,
                                                uint32_t op_sel, uint32_t F,
                                                uint32_t esize, uint32_t d_idx,
                                                uint32_t m_idx, uint32_t regs);
};
