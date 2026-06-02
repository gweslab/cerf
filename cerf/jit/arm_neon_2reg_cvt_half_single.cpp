#include "arm_neon_2reg_cvt_half_single.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeon2RegCvtHalfSingle);

namespace {

/* IEEE 754 binary16 → binary32 (FPHalfToSingle, ARM ARM A2.7, line 5093).
   NEON FZ=1 implicit: denormal half inputs flush to ±0. NaN quietens per
   spec line 5100: sign | exp_all_ones | quiet_bit | low9 of half mantissa. */
inline uint32_t HalfToSingle(uint16_t h) {
    const uint32_t sign     = static_cast<uint32_t>(h & 0x8000u) << 16;
    const uint32_t exp      = static_cast<uint32_t>(h >> 10) & 0x1Fu;
    const uint32_t mantissa = static_cast<uint32_t>(h) & 0x3FFu;

    if (exp == 0u) {
        /* ±0 or denormal (denormal flushed to ±0 per FZ=1). */
        return sign;
    }
    if (exp == 0x1Fu) {
        if (mantissa == 0u) {
            return sign | 0x7F800000u;
        }
        /* NaN — force quiet bit (bit 22), narrow mantissa to high 9 bits. */
        return sign | 0x7F800000u | 0x00400000u
             | ((mantissa & 0x1FFu) << 13);
    }
    /* Normal: rebias 15 → 127 (single_exp = half_exp + 112). */
    return sign | ((exp + 112u) << 23) | (mantissa << 13);
}

/* IEEE 754 binary32 → binary16 (FPSingleToHalf, ARM ARM A2.7, line 5114).
   Round-to-nearest-even on mantissa narrowing (23 → 10 bits). NEON FZ=1:
   denormal half outputs flush to ±0. Overflow → ±Inf. */
inline uint16_t SingleToHalf(uint32_t f) {
    const uint16_t sign = static_cast<uint16_t>((f >> 16) & 0x8000u);
    const uint32_t exp      = (f >> 23) & 0xFFu;
    const uint32_t mantissa = f & 0x7FFFFFu;

    if (exp == 0xFFu) {
        if (mantissa == 0u) {
            return sign | 0x7C00u;
        }
        /* NaN — quiet bit set (bit 9), narrow mantissa from bits[22:13]. */
        return sign | 0x7E00u
             | static_cast<uint16_t>((mantissa >> 13) & 0x1FFu);
    }
    if (exp == 0u) {
        /* ±0 or denormal (FZ=1). */
        return sign;
    }
    int new_exp = static_cast<int>(exp) - 127 + 15;
    if (new_exp >= 0x1F) {
        return sign | 0x7C00u;  /* overflow → ±Inf */
    }
    if (new_exp <= 0) {
        return sign;            /* underflow → ±0 (FZ=1) */
    }

    /* RtN-even: round bit is bit 12 of single mantissa; sticky is bits[11:0]. */
    uint32_t rounded = mantissa >> 13;
    const uint32_t round_bit = (mantissa >> 12) & 1u;
    const uint32_t sticky    = mantissa & 0xFFFu;
    if (round_bit == 1u && (sticky != 0u || (rounded & 1u) == 1u)) {
        rounded += 1u;
        if (rounded == 0x400u) {
            /* Mantissa overflowed to 2^10 → bump exponent. */
            rounded = 0u;
            new_exp += 1;
            if (new_exp >= 0x1F) {
                return sign | 0x7C00u;
            }
        }
    }
    return sign
         | static_cast<uint16_t>(static_cast<uint32_t>(new_exp) << 10)
         | static_cast<uint16_t>(rounded & 0x3FFu);
}

}  /* namespace */

void ArmNeon2RegCvtHalfSingle::HandleCvtHalfSingle(uint32_t op_sel,
                                                   uint32_t d_idx,
                                                   uint32_t m_idx) {
    auto* state = emu_.Get<ArmCpu>().State();

    if (op_sel == kHalfToSingle) {
        /* Source D-reg (8 bytes = 4 halves), dest Q-reg (16 bytes = 4 singles). */
        const uint8_t* src =
            reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]);
        uint8_t res[16];
        for (uint32_t e = 0; e < 4u; ++e) {
            uint16_t h;
            std::memcpy(&h, src + e * 2u, 2);
            const uint32_t f = HalfToSingle(h);
            std::memcpy(res + e * 4u, &f, 4);
        }
        std::memcpy(&state->vfp_d[d_idx],     res,     8);
        std::memcpy(&state->vfp_d[d_idx + 1], res + 8, 8);
    } else {
        /* Source Q-reg, dest D-reg. */
        uint8_t src_q[16];
        std::memcpy(src_q,     &state->vfp_d[m_idx],     8);
        std::memcpy(src_q + 8, &state->vfp_d[m_idx + 1], 8);
        uint8_t res[8];
        for (uint32_t e = 0; e < 4u; ++e) {
            uint32_t f;
            std::memcpy(&f, src_q + e * 4u, 4);
            const uint16_t h = SingleToHalf(f);
            std::memcpy(res + e * 2u, &h, 2);
        }
        std::memcpy(&state->vfp_d[d_idx], res, 8);
    }
}

void __cdecl ArmNeon2RegCvtHalfSingle::HandleCvtHalfSingleHelper(
        ArmNeon2RegCvtHalfSingle* svc, uint32_t op_sel,
        uint32_t d_idx, uint32_t m_idx) {
    svc->HandleCvtHalfSingle(op_sel, d_idx, m_idx);
}
