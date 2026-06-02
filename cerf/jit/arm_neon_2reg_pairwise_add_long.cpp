#include "arm_neon_2reg_pairwise_add_long.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"
#include "arm_vfp.h"

REGISTER_SERVICE(ArmNeon2RegPairwiseAddLong);

void ArmNeon2RegPairwiseAddLong::HandlePairwiseAddLong(uint32_t op_sel, uint32_t U,
                                                       uint32_t esize, uint32_t d_idx,
                                                       uint32_t m_idx, uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes     = esize / 8u;
    const uint32_t elements   = 8u / ebytes;
    const uint32_t h          = elements / 2u;
    const uint32_t out_esize  = 2u * esize;
    const uint32_t out_ebytes = 2u * ebytes;

    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* m_src =
            reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx + r]);
        const uint8_t* d_src =
            reinterpret_cast<const uint8_t*>(&state->vfp_d[d_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < h; ++e) {
            const uint8_t* p1 = m_src + (2u * e + 0u) * ebytes;
            const uint8_t* p2 = m_src + (2u * e + 1u) * ebytes;
            uint64_t result_bits;
            if (U != 0u) {
                const uint64_t op1 = ArmVfp::LoadIntU(p1, esize);
                const uint64_t op2 = ArmVfp::LoadIntU(p2, esize);
                uint64_t sum = op1 + op2;
                if (op_sel == kPadal) {
                    const uint64_t acc =
                        ArmVfp::LoadIntU(d_src + e * out_ebytes, out_esize);
                    sum = acc + sum;
                }
                result_bits = sum;
            } else {
                const int64_t op1 = ArmVfp::LoadIntS(p1, esize);
                const int64_t op2 = ArmVfp::LoadIntS(p2, esize);
                int64_t sum = op1 + op2;
                if (op_sel == kPadal) {
                    const int64_t acc =
                        ArmVfp::LoadIntS(d_src + e * out_ebytes, out_esize);
                    sum = acc + sum;
                }
                result_bits = static_cast<uint64_t>(sum);
            }
            /* Truncate to out_ebytes low bytes per ARM ARM "result<2*esize-1:0>". */
            std::memcpy(res + e * out_ebytes, &result_bits, out_ebytes);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeon2RegPairwiseAddLong::HandlePairwiseAddLongHelper(
        ArmNeon2RegPairwiseAddLong* svc, uint32_t op_sel, uint32_t U,
        uint32_t esize, uint32_t d_idx, uint32_t m_idx, uint32_t regs) {
    svc->HandlePairwiseAddLong(op_sel, U, esize, d_idx, m_idx, regs);
}
