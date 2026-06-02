#include "arm_neon_2reg_cvt_int_fp.h"

#include <cmath>
#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeon2RegCvtIntFp);

namespace {

/* fp→s32 with Round-to-Zero (truncation, ARM ARM A8.8.305 line 41314):
   NaN→0, out-of-range saturates. Host (int32_t)f is RtZ-defined only in
   the representable range — out-of-range cast is UB; explicit saturation
   avoids it. */
inline int32_t FpToS32(float f) {
    if (std::isnan(f))               return 0;
    if (f >=  2147483648.0f)         return 0x7FFFFFFF;       /* >= 2^31 */
    if (f <  -2147483648.0f)         return static_cast<int32_t>(0x80000000u);
    return static_cast<int32_t>(f);
}

inline uint32_t FpToU32(float f) {
    if (std::isnan(f))               return 0;
    if (f >=  4294967296.0f)         return 0xFFFFFFFFu;      /* >= 2^32 */
    if (f <=  0.0f)                  return 0;
    return static_cast<uint32_t>(f);
}

}  /* namespace */

void ArmNeon2RegCvtIntFp::HandleCvtIntFp(uint32_t op_sel, uint32_t d_idx,
                                         uint32_t m_idx, uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    /* esize=32, elements=2 per D-reg (decoder UNDs other sizes). */
    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* src =
            reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < 2u; ++e) {
            uint32_t in;
            std::memcpy(&in, src + e * 4u, 4);
            uint32_t out;
            if (op_sel == kIntSToFp) {
                /* C++ int→float uses current rounding (default RtN). */
                const float f = static_cast<float>(static_cast<int32_t>(in));
                std::memcpy(&out, &f, 4);
            } else if (op_sel == kIntUToFp) {
                const float f = static_cast<float>(in);
                std::memcpy(&out, &f, 4);
            } else {
                float f;
                std::memcpy(&f, &in, 4);
                if (op_sel == kFpToIntS) {
                    const int32_t i = FpToS32(f);
                    std::memcpy(&out, &i, 4);
                } else {
                    out = FpToU32(f);
                }
            }
            std::memcpy(res + e * 4u, &out, 4);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeon2RegCvtIntFp::HandleCvtIntFpHelper(ArmNeon2RegCvtIntFp* svc,
                                                       uint32_t op_sel,
                                                       uint32_t d_idx,
                                                       uint32_t m_idx,
                                                       uint32_t regs) {
    svc->HandleCvtIntFp(op_sel, d_idx, m_idx, regs);
}
