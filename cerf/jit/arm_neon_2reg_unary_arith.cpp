#include "arm_neon_2reg_unary_arith.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"
#include "arm_vfp.h"

REGISTER_SERVICE(ArmNeon2RegUnaryArith);

void ArmNeon2RegUnaryArith::HandleUnaryArith(uint32_t op_sel, uint32_t F,
                                             uint32_t esize, uint32_t d_idx,
                                             uint32_t m_idx, uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes   = esize / 8u;
    const uint32_t elements = 8u / ebytes;

    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* src = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < elements; ++e) {
            if (F != 0u) {
                /* .F32 — decoder rejects esize != 32 in this branch. */
                float v;
                std::memcpy(&v, src + e * 4u, 4);
                const float w = (op_sel == kAbs) ? ArmVfp::FPAbsS(v)
                                                 : ArmVfp::FPNegS(v);
                std::memcpy(res + e * 4u, &w, 4);
            } else {
                /* Integer: sign-extend, 2's-complement negate in unsigned
                   (well-defined for INT_MIN), truncate to esize on store. */
                const uint32_t uv  =
                    static_cast<uint32_t>(ArmVfp::LoadIntS(src + e * ebytes, esize));
                const uint32_t neg = 0u - uv;
                const uint32_t out = (op_sel == kAbs)
                                   ? ((static_cast<int32_t>(uv) < 0) ? neg : uv)
                                   : neg;
                std::memcpy(res + e * ebytes, &out, ebytes);
            }
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeon2RegUnaryArith::HandleUnaryArithHelper(
        ArmNeon2RegUnaryArith* svc, uint32_t op_sel, uint32_t F,
        uint32_t esize, uint32_t d_idx, uint32_t m_idx, uint32_t regs) {
    svc->HandleUnaryArith(op_sel, F, esize, d_idx, m_idx, regs);
}
