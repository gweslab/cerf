#include "arm_neon_3same_fp_compare.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"
#include "arm_vfp.h"

REGISTER_SERVICE(ArmNeon3SameFpCompare);

void ArmNeon3SameFpCompare::Handle3SameFpCompare(uint32_t op_sel, uint32_t d_idx,
                                                 uint32_t n_idx, uint32_t m_idx,
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
            bool passed;
            switch (op_sel) {
                case kEq: passed = ArmVfp::FPCompareEqS(fn, fm); break;
                case kGe: passed = ArmVfp::FPCompareGeS(fn, fm); break;
                default:  /* kGt */
                    passed = ArmVfp::FPCompareGtS(fn, fm);
                    break;
            }
            const uint32_t mask = passed ? 0xFFFFFFFFu : 0u;
            std::memcpy(res + e * 4u, &mask, 4);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeon3SameFpCompare::Handle3SameFpCompareHelper(
        ArmNeon3SameFpCompare* svc, uint32_t op_sel, uint32_t d_idx,
        uint32_t n_idx, uint32_t m_idx, uint32_t regs) {
    svc->Handle3SameFpCompare(op_sel, d_idx, n_idx, m_idx, regs);
}
