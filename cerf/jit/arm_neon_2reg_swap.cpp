#include "arm_neon_2reg_swap.h"

#include <cstdint>
#include <utility>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeon2RegSwap);

void ArmNeon2RegSwap::HandleSwap(uint32_t d_idx, uint32_t m_idx, uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    /* d == m case: spec says D[d+r] = UNKNOWN (A8.8.418 line 52637). A no-op
       swap leaves the register unchanged, a valid UNKNOWN result. */
    for (uint32_t r = 0; r < regs; ++r) {
        std::swap(state->vfp_d[d_idx + r], state->vfp_d[m_idx + r]);
    }
}

void __cdecl ArmNeon2RegSwap::HandleSwapHelper(ArmNeon2RegSwap* svc,
                                               uint32_t d_idx, uint32_t m_idx,
                                               uint32_t regs) {
    svc->HandleSwap(d_idx, m_idx, regs);
}
