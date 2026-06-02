#include "arm_neon_3same_fp_recip_step.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"
#include "arm_vfp.h"

REGISTER_SERVICE(ArmNeon3SameFpRecipStep);

void ArmNeon3SameFpRecipStep::Handle3SameFpRecipStep(uint32_t op_sel,
                                                    uint32_t d_idx,
                                                    uint32_t n_idx,
                                                    uint32_t m_idx,
                                                    uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* n_src =
            reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx + r]);
        const uint8_t* m_src =
            reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < 2u; ++e) {
            float fn, fm;
            std::memcpy(&fn, n_src + e * 4u, 4);
            std::memcpy(&fm, m_src + e * 4u, 4);
            const float result = (op_sel == kRsqrts)
                                     ? ArmVfp::FPRSqrtStepS(fn, fm)
                                     : ArmVfp::FPRecipStepS(fn, fm);
            std::memcpy(res + e * 4u, &result, 4);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeon3SameFpRecipStep::Handle3SameFpRecipStepHelper(
        ArmNeon3SameFpRecipStep* svc, uint32_t op_sel, uint32_t d_idx,
        uint32_t n_idx, uint32_t m_idx, uint32_t regs) {
    svc->Handle3SameFpRecipStep(op_sel, d_idx, n_idx, m_idx, regs);
}
