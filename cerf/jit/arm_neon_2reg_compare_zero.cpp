#include "arm_neon_2reg_compare_zero.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"
#include "arm_vfp.h"

REGISTER_SERVICE(ArmNeon2RegCompareZero);

namespace {

inline bool TestIntegerVsZero(uint32_t op_sel, int32_t v) {
    using S = ArmNeon2RegCompareZero;
    switch (op_sel) {
        case S::kCgt: return v >  0;
        case S::kCge: return v >= 0;
        case S::kCeq: return v == 0;
        case S::kCle: return v <= 0;
        default:      return v <  0;  /* kClt */
    }
}

inline bool TestFloatVsZero(uint32_t op_sel, float v) {
    using S = ArmNeon2RegCompareZero;
    switch (op_sel) {
        case S::kCgt: return ArmVfp::FPCompareGtS(v, 0.0f);
        case S::kCge: return ArmVfp::FPCompareGeS(v, 0.0f);
        case S::kCeq: return ArmVfp::FPCompareEqS(v, 0.0f);
        case S::kCle: return ArmVfp::FPCompareLeS(v, 0.0f);
        default:      return ArmVfp::FPCompareLtS(v, 0.0f);  /* kClt */
    }
}

}  /* namespace */

void ArmNeon2RegCompareZero::HandleCompareZero(uint32_t op_sel, uint32_t F,
                                               uint32_t esize, uint32_t d_idx,
                                               uint32_t m_idx, uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes   = esize / 8u;
    const uint32_t elements = 8u / ebytes;

    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* src =
            reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < elements; ++e) {
            bool passed;
            if (F != 0u) {
                /* .F32 — decoder rejects esize != 32. */
                float v;
                std::memcpy(&v, src + e * 4u, 4);
                passed = TestFloatVsZero(op_sel, v);
            } else {
                /* Signed integer for VCGT/VCGE/VCLT/VCLE; VCEQ same answer
                   either signedness ("==" doesn't care about sign-extend). */
                const int32_t v =
                    static_cast<int32_t>(ArmVfp::LoadIntS(src + e * ebytes, esize));
                passed = TestIntegerVsZero(op_sel, v);
            }
            /* Result lane = all-ones if test passed, else all-zeros. */
            const uint32_t mask = passed ? 0xFFFFFFFFu : 0u;
            std::memcpy(res + e * ebytes, &mask, ebytes);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeon2RegCompareZero::HandleCompareZeroHelper(
        ArmNeon2RegCompareZero* svc, uint32_t op_sel, uint32_t F,
        uint32_t esize, uint32_t d_idx, uint32_t m_idx, uint32_t regs) {
    svc->HandleCompareZero(op_sel, F, esize, d_idx, m_idx, regs);
}
