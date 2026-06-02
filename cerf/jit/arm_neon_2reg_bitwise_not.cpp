#include "arm_neon_2reg_bitwise_not.h"

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeon2RegBitwiseNot);

void ArmNeon2RegBitwiseNot::HandleMvn(uint32_t d_idx, uint32_t m_idx,
                                      uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    for (uint32_t r = 0; r < regs; ++r) {
        state->vfp_d[d_idx + r] = ~state->vfp_d[m_idx + r];
    }
}

void __cdecl ArmNeon2RegBitwiseNot::HandleMvnHelper(ArmNeon2RegBitwiseNot* svc,
                                                    uint32_t d_idx, uint32_t m_idx,
                                                    uint32_t regs) {
    svc->HandleMvn(d_idx, m_idx, regs);
}
