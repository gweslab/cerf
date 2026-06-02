#pragma once

#include <cstdint>

#include "../core/service.h"

/* VTRN / VUZP / VZIP (A8.8.420 / A8.8.422 / A8.8.423). */
class ArmNeon2RegShuffle : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kTrn = 0u;
    static constexpr uint32_t kUzp = 1u;
    static constexpr uint32_t kZip = 2u;

    void HandleShuffle(uint32_t op_sel, uint32_t esize, uint32_t Q,
                       uint32_t d_idx, uint32_t m_idx);

    static void __cdecl HandleShuffleHelper(ArmNeon2RegShuffle* svc,
                                            uint32_t op_sel, uint32_t esize,
                                            uint32_t Q, uint32_t d_idx,
                                            uint32_t m_idx);
};
