#include "arm_neon_3same_fp_pair_min_max.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"
#include "arm_vfp.h"

REGISTER_SERVICE(ArmNeon3SameFpPairMinMax);

void ArmNeon3SameFpPairMinMax::Handle3SameFpPairMinMax(uint32_t op_sel,
                                                       uint32_t d_idx,
                                                       uint32_t n_idx,
                                                       uint32_t m_idx) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint8_t* n_src =
        reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx]);
    const uint8_t* m_src =
        reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]);
    float n0, n1, m0, m1;
    std::memcpy(&n0, n_src,         4);
    std::memcpy(&n1, n_src + 4u,    4);
    std::memcpy(&m0, m_src,         4);
    std::memcpy(&m1, m_src + 4u,    4);
    const float lo = (op_sel == kMin) ? ArmVfp::FPMinS(n0, n1)
                                      : ArmVfp::FPMaxS(n0, n1);
    const float hi = (op_sel == kMin) ? ArmVfp::FPMinS(m0, m1)
                                      : ArmVfp::FPMaxS(m0, m1);
    uint8_t res[8];
    std::memcpy(res,      &lo, 4);
    std::memcpy(res + 4u, &hi, 4);
    std::memcpy(&state->vfp_d[d_idx], res, 8);
}

void __cdecl ArmNeon3SameFpPairMinMax::Handle3SameFpPairMinMaxHelper(
        ArmNeon3SameFpPairMinMax* svc, uint32_t op_sel, uint32_t d_idx,
        uint32_t n_idx, uint32_t m_idx) {
    svc->Handle3SameFpPairMinMax(op_sel, d_idx, n_idx, m_idx);
}
