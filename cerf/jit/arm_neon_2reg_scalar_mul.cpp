#include "arm_neon_2reg_scalar_mul.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"
#include "arm_vfp.h"

REGISTER_SERVICE(ArmNeon2RegScalarMul);

namespace {

inline float LoadFloatElement(const uint8_t* p) {
    float v;
    std::memcpy(&v, p, 4);
    return v;
}

}  /* namespace */

void ArmNeon2RegScalarMul::HandleScalarMul(uint32_t op_sel, uint32_t F,
                                           uint32_t esize, uint32_t d_idx,
                                           uint32_t n_idx, uint32_t m_idx,
                                           uint32_t index, uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes   = esize / 8u;
    const uint32_t elements = 8u / ebytes;

    /* Scalar lane fetched once, reused across all elements + Q halves. */
    const uint8_t* scalar_src =
        reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]);
    uint32_t scalar_u = 0;
    float    scalar_f = 0.0f;
    if (F != 0u) {
        scalar_f = LoadFloatElement(scalar_src + index * 4u);
    } else {
        scalar_u =
            static_cast<uint32_t>(ArmVfp::LoadIntU(scalar_src + index * ebytes, esize));
    }

    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* n_src =
            reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx + r]);
        const uint8_t* d_src =
            reinterpret_cast<const uint8_t*>(&state->vfp_d[d_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < elements; ++e) {
            if (F != 0u) {
                /* .F32 — decoder rejects esize != 32. */
                const float n_f = LoadFloatElement(n_src + e * 4u);
                const float prod = ArmVfp::FPMulS(n_f, scalar_f);
                float result;
                if (op_sel == kMul) {
                    result = prod;
                } else {
                    const float d_f = LoadFloatElement(d_src + e * 4u);
                    result = (op_sel == kMla) ? ArmVfp::FPAddS(d_f, prod)
                                              : ArmVfp::FPSubS(d_f, prod);
                }
                std::memcpy(res + e * 4u, &result, 4);
            } else {
                /* Integer — spec "unsigned = FALSE; Don't care: TRUE produces
                   same functionality": modular `low esize bits` is identical
                   whether we sign- or zero-extend before the multiply. */
                const uint32_t n_u  =
                    static_cast<uint32_t>(ArmVfp::LoadIntU(n_src + e * ebytes, esize));
                const uint32_t prod = n_u * scalar_u;
                uint32_t result;
                if (op_sel == kMul) {
                    result = prod;
                } else {
                    const uint32_t d_u =
                        static_cast<uint32_t>(ArmVfp::LoadIntU(d_src + e * ebytes, esize));
                    result = (op_sel == kMla) ? (d_u + prod) : (d_u - prod);
                }
                std::memcpy(res + e * ebytes, &result, ebytes);
            }
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeon2RegScalarMul::HandleScalarMulHelper(
        ArmNeon2RegScalarMul* svc, uint32_t op_sel, uint32_t F,
        uint32_t esize, uint32_t d_idx, uint32_t n_idx, uint32_t m_idx,
        uint32_t index, uint32_t regs) {
    svc->HandleScalarMul(op_sel, F, esize, d_idx, n_idx, m_idx, index, regs);
}
