#include "arm_neon_2reg_reciprocal.h"

#include <cmath>
#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"
#include "arm_vfp.h"

REGISTER_SERVICE(ArmNeon2RegReciprocal);

namespace {

inline uint32_t Bits(float f) {
    uint32_t b;
    std::memcpy(&b, &f, 4);
    return b;
}

inline float FromBits(uint32_t b) {
    float f;
    std::memcpy(&f, &b, 4);
    return f;
}

inline uint64_t DpBits(double d) {
    uint64_t b;
    std::memcpy(&b, &d, 8);
    return b;
}

inline double FromDpBits(uint64_t b) {
    double d;
    std::memcpy(&d, &b, 8);
    return d;
}

/* UnsignedRecipEstimate per ARM ARM A2-85 (lines 4738-4757). */
uint32_t UnsignedRecipEstimate(uint32_t operand) {
    if ((operand & 0x80000000u) == 0u) {
        return 0xFFFFFFFFu;
    }
    /* dp_operand = '0 01111111110' : operand<30:0> : Zeros(21).
       Sign=0, biased exponent=1022 (= 0x3FE), fraction = bits[51:21]. */
    const uint64_t dp_bits =
        (uint64_t{0x3FE} << 52) | (static_cast<uint64_t>(operand & 0x7FFFFFFFu) << 21);
    const double estimate = ArmVfp::RecipEstimate(FromDpBits(dp_bits));
    const uint64_t est_bits = DpBits(estimate);
    /* result = '1' : estimate<51:21>  (31-bit slice). */
    return 0x80000000u | static_cast<uint32_t>((est_bits >> 21) & 0x7FFFFFFFu);
}

/* UnsignedRSqrtEstimate per ARM ARM A2-87 (lines 4927-4949). */
uint32_t UnsignedRSqrtEstimate(uint32_t operand) {
    if ((operand & 0xC0000000u) == 0u) {
        /* operand <= 0x3FFFFFFF */
        return 0xFFFFFFFFu;
    }
    uint64_t dp_bits;
    if (operand & 0x80000000u) {
        /* dp_operand = '0 01111111110' : operand<30:0> : Zeros(21). */
        dp_bits = (uint64_t{0x3FE} << 52)
                | (static_cast<uint64_t>(operand & 0x7FFFFFFFu) << 21);
    } else {
        /* operand<31:30> == 01 → dp_operand = '0 01111111101' :
           operand<29:0> : Zeros(22). */
        dp_bits = (uint64_t{0x3FD} << 52)
                | (static_cast<uint64_t>(operand & 0x3FFFFFFFu) << 22);
    }
    const double estimate = ArmVfp::RecipSqrtEstimate(FromDpBits(dp_bits));
    const uint64_t est_bits = DpBits(estimate);
    return 0x80000000u | static_cast<uint32_t>((est_bits >> 21) & 0x7FFFFFFFu);
}

/* FPRecipEstimate per ARM ARM A2-85 (lines 4700-4733). */
uint32_t FPRecipEstimate(uint32_t operand_bits) {
    const uint32_t sign_bit = operand_bits & 0x80000000u;
    const uint32_t exp_bits = (operand_bits >> 23) & 0xFFu;
    const uint32_t frac_bits = operand_bits & 0x7FFFFFu;

    /* Treat denormals as zero (flush-to-zero implicit in NEON). */
    const bool is_zero    = (exp_bits == 0u && frac_bits == 0u);
    const bool is_denorm  = (exp_bits == 0u && frac_bits != 0u);
    const bool is_inf     = (exp_bits == 0xFFu && frac_bits == 0u);
    const bool is_nan     = (exp_bits == 0xFFu && frac_bits != 0u);

    if (is_nan) {
        /* Default-NaN propagation (NEON FPSCR.DN=1 implicit). */
        return 0x7FC00000u;
    }
    if (is_inf) {
        return sign_bit;  /* ±Inf → ±0 */
    }
    if (is_zero || is_denorm) {
        /* ±0 (or denormal flushed to ±0) → ±Inf, FPSCR.DivByZero would
           be raised on real HW. CERF doesn't track FPSCR exception bits. */
        return sign_bit | 0x7F800000u;
    }
    /* |x| >= 2^126 → ±0 (underflow). exp_bits == 253 corresponds to 2^126
       (biased 253 - 127 = 126). */
    if (exp_bits >= 253u) {
        return sign_bit;
    }
    /* scaled = '0 01111111110' : operand<22:0> : Zeros(29) — i.e.,
       biased exp=1022 (= 0x3FE), sign=0, fraction = high 23 bits of float
       mantissa placed at bits[51:29] of double. */
    const uint64_t scaled = (uint64_t{0x3FE} << 52)
                          | (static_cast<uint64_t>(frac_bits) << 29);
    const double estimate = ArmVfp::RecipEstimate(FromDpBits(scaled));
    const uint64_t est_bits = DpBits(estimate);
    /* result_exp = 253 - exp_bits (in float bias 127). */
    const uint32_t result_exp = 253u - exp_bits;
    /* result = sign : result_exp<7:0> : estimate<51:29>. */
    return sign_bit
         | ((result_exp & 0xFFu) << 23)
         | static_cast<uint32_t>((est_bits >> 29) & 0x7FFFFFu);
}

/* FPRSqrtEstimate per ARM ARM A2-87 (lines 4878-4922). */
uint32_t FPRSqrtEstimate(uint32_t operand_bits) {
    const uint32_t sign_bit  = operand_bits & 0x80000000u;
    const uint32_t exp_bits  = (operand_bits >> 23) & 0xFFu;
    const uint32_t frac_bits = operand_bits & 0x7FFFFFu;
    const bool sign = sign_bit != 0u;

    const bool is_zero   = (exp_bits == 0u   && frac_bits == 0u);
    const bool is_denorm = (exp_bits == 0u   && frac_bits != 0u);
    const bool is_inf    = (exp_bits == 0xFFu && frac_bits == 0u);
    const bool is_nan    = (exp_bits == 0xFFu && frac_bits != 0u);

    if (is_nan) {
        return 0x7FC00000u;
    }
    if (is_zero || is_denorm) {
        /* ±0 → ±Inf, FPExc_DivideByZero on real HW. */
        return sign_bit | 0x7F800000u;
    }
    if (sign) {
        /* Negative → default NaN, FPExc_InvalidOp. */
        return 0x7FC00000u;
    }
    if (is_inf) {
        return 0u;  /* +Inf → +0 */
    }
    /* Scale to [0.25, 1.0) preserving exponent parity. */
    uint64_t scaled;
    if ((operand_bits & (1u << 23)) == 0u) {
        /* operand<23>==0 → biased exp=1022 (= 0x3FE). */
        scaled = (uint64_t{0x3FE} << 52) | (static_cast<uint64_t>(frac_bits) << 29);
    } else {
        /* operand<23>==1 → biased exp=1021 (= 0x3FD). */
        scaled = (uint64_t{0x3FD} << 52) | (static_cast<uint64_t>(frac_bits) << 29);
    }
    const double estimate = ArmVfp::RecipSqrtEstimate(FromDpBits(scaled));
    const uint64_t est_bits = DpBits(estimate);
    /* result_exp = (380 - exp_bits) DIV 2  (float bias 127, in floor div). */
    const uint32_t result_exp = (380u - exp_bits) >> 1;
    /* result = '0' : result_exp<7:0> : estimate<51:29>. */
    return ((result_exp & 0xFFu) << 23)
         | static_cast<uint32_t>((est_bits >> 29) & 0x7FFFFFu);
}

}  /* namespace */

void ArmNeon2RegReciprocal::HandleReciprocal(uint32_t op_sel, uint32_t F,
                                             uint32_t d_idx, uint32_t m_idx,
                                             uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    /* esize=32 always (decoder UNDs other sizes); 2 elements per D-reg. */
    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* src =
            reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < 2u; ++e) {
            uint32_t in;
            std::memcpy(&in, src + e * 4u, 4);
            uint32_t out;
            if (op_sel == kRecpe) {
                out = (F != 0u) ? FPRecipEstimate(in) : UnsignedRecipEstimate(in);
            } else {
                out = (F != 0u) ? FPRSqrtEstimate(in) : UnsignedRSqrtEstimate(in);
            }
            std::memcpy(res + e * 4u, &out, 4);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeon2RegReciprocal::HandleReciprocalHelper(
        ArmNeon2RegReciprocal* svc, uint32_t op_sel, uint32_t F,
        uint32_t d_idx, uint32_t m_idx, uint32_t regs) {
    svc->HandleReciprocal(op_sel, F, d_idx, m_idx, regs);
}
