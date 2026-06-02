#include "arm_neon_2regscalar.h"

#include <cstdint>
#include <cstring>
#include <limits>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeon2RegScalar);

void ArmNeon2RegScalar::HandleScalarMlsMlaLong(uint32_t op, uint32_t d_idx,
                                               uint32_t n_idx, uint32_t m_idx,
                                               uint32_t esize, uint32_t index,
                                               uint32_t u) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t in_ebytes  = esize / 8u;
    const uint32_t out_ebytes = 2u * in_ebytes;
    const uint32_t elements   = 8u / in_ebytes;
    const uint32_t sh         = 64u - esize;
    const bool is_mull     = (op == kS2sMull);
    const bool is_subtract = (op == kS2sMlsl);
    const bool is_unsigned = (u != 0u);

    uint64_t scalar_raw = 0;
    std::memcpy(&scalar_raw,
                reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]) +
                    index * in_ebytes,
                in_ebytes);

    const uint8_t* dn = reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx]);

    uint8_t dd[16] = {0};
    if (!is_mull) {
        std::memcpy(dd,     &state->vfp_d[d_idx],     8);
        std::memcpy(dd + 8, &state->vfp_d[d_idx + 1], 8);
    }

    uint8_t res[16];
    for (uint32_t e = 0; e < elements; ++e) {
        uint64_t op1_raw = 0;
        std::memcpy(&op1_raw, dn + e * in_ebytes, in_ebytes);

        uint64_t product;
        if (is_unsigned) {
            product = op1_raw * scalar_raw;
        } else {
            const int64_t op1_s    = static_cast<int64_t>(op1_raw   << sh) >> sh;
            const int64_t scalar_s = static_cast<int64_t>(scalar_raw << sh) >> sh;
            product = static_cast<uint64_t>(op1_s * scalar_s);
        }

        uint64_t result;
        if (is_mull) {
            result = product;
        } else {
            uint64_t accum = 0;
            std::memcpy(&accum, dd + e * out_ebytes, out_ebytes);
            result = is_subtract ? (accum - product) : (accum + product);
        }
        std::memcpy(res + e * out_ebytes, &result, out_ebytes);
    }
    std::memcpy(&state->vfp_d[d_idx],     res,     8);
    std::memcpy(&state->vfp_d[d_idx + 1], res + 8, 8);
}

void __cdecl ArmNeon2RegScalar::HandleScalarMlsMlaLongHelper(ArmNeon2RegScalar* svc,
                                                             uint32_t op,
                                                             uint32_t d_idx, uint32_t n_idx,
                                                             uint32_t m_idx, uint32_t esize,
                                                             uint32_t index, uint32_t u) {
    svc->HandleScalarMlsMlaLong(op, d_idx, n_idx, m_idx, esize, index, u);
}

void ArmNeon2RegScalar::HandleScalarMulLongSat(uint32_t op, uint32_t d_idx,
                                               uint32_t n_idx, uint32_t m_idx,
                                               uint32_t esize, uint32_t index) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t in_ebytes  = esize / 8u;
    const uint32_t out_ebytes = 2u * in_ebytes;
    const uint32_t elements   = 8u / in_ebytes;
    const uint32_t sh         = 64u - esize;
    const uint32_t out_bits   = 2u * esize;
    const bool is_mull     = (op == kS2sVqdmull);
    const bool is_subtract = (op == kS2sVqdmlsl);
    const int64_t  MIN_OP    = -(static_cast<int64_t>(1) << (esize - 1u));
    const int64_t  MAX_OUT   = (out_bits == 64u)
                                   ? std::numeric_limits<int64_t>::max()
                                   : ((static_cast<int64_t>(1) << (out_bits - 1u)) - 1);
    const int64_t  MIN_OUT   = (out_bits == 64u)
                                   ? std::numeric_limits<int64_t>::min()
                                   : (-(static_cast<int64_t>(1) << (out_bits - 1u)));
    const uint64_t sign_bit  = static_cast<uint64_t>(1) << (out_bits - 1u);

    uint64_t scalar_raw = 0;
    std::memcpy(&scalar_raw,
                reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]) +
                    index * in_ebytes,
                in_ebytes);
    const int64_t scalar_s = static_cast<int64_t>(scalar_raw << sh) >> sh;

    const uint8_t* dn = reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx]);

    uint8_t dd[16] = {0};
    if (!is_mull) {
        std::memcpy(dd,     &state->vfp_d[d_idx],     8);
        std::memcpy(dd + 8, &state->vfp_d[d_idx + 1], 8);
    }

    uint8_t res[16];
    bool qc_any = false;
    for (uint32_t e = 0; e < elements; ++e) {
        uint64_t op1_raw = 0;
        std::memcpy(&op1_raw, dn + e * in_ebytes, in_ebytes);
        const int64_t op1_s = static_cast<int64_t>(op1_raw << sh) >> sh;

        int64_t product;
        bool sat1 = false;
        if (op1_s == MIN_OP && scalar_s == MIN_OP) {
            product = MAX_OUT;
            sat1 = true;
        } else {
            product = 2 * (op1_s * scalar_s);
        }

        int64_t final_result;
        bool sat2 = false;
        if (is_mull) {
            final_result = product;
        } else {
            uint64_t accum_raw = 0;
            std::memcpy(&accum_raw, dd + e * out_ebytes, out_ebytes);
            const int64_t accum_s = (out_bits == 64u)
                ? static_cast<int64_t>(accum_raw)
                : (static_cast<int64_t>(accum_raw << (64u - out_bits)) >> (64u - out_bits));

            const uint64_t a = static_cast<uint64_t>(accum_s);
            const uint64_t b = static_cast<uint64_t>(product);
            const uint64_t c = is_subtract ? (a - b) : (a + b);
            const uint64_t a_sign = a & sign_bit;
            const uint64_t b_sign = b & sign_bit;
            const uint64_t c_sign = c & sign_bit;
            const bool overflowed = is_subtract
                ? ((a_sign != b_sign) && (c_sign != a_sign))
                : ((a_sign == b_sign) && (c_sign != a_sign));
            if (overflowed) {
                final_result = (a_sign != 0u) ? MIN_OUT : MAX_OUT;
                sat2 = true;
            } else {
                final_result = static_cast<int64_t>(c);
            }
        }

        if (sat1 || sat2) {
            qc_any = true;
        }

        const uint64_t result_raw = static_cast<uint64_t>(final_result);
        std::memcpy(res + e * out_ebytes, &result_raw, out_ebytes);
    }
    if (qc_any) {
        state->fpscr |= (1u << 27);
    }
    std::memcpy(&state->vfp_d[d_idx],     res,     8);
    std::memcpy(&state->vfp_d[d_idx + 1], res + 8, 8);
}

void __cdecl ArmNeon2RegScalar::HandleScalarMulLongSatHelper(ArmNeon2RegScalar* svc,
                                                             uint32_t op,
                                                             uint32_t d_idx, uint32_t n_idx,
                                                             uint32_t m_idx, uint32_t esize,
                                                             uint32_t index) {
    svc->HandleScalarMulLongSat(op, d_idx, n_idx, m_idx, esize, index);
}

void ArmNeon2RegScalar::HandleScalarMulhSat(uint32_t op, uint32_t d_idx,
                                            uint32_t n_idx, uint32_t m_idx,
                                            uint32_t esize, uint32_t index,
                                            uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes   = esize / 8u;
    const uint32_t elements = 8u / ebytes;
    const uint32_t sh       = 64u - esize;
    const bool is_rounding = (op == kS2sVqrdmulh);
    const int64_t MIN_OP  = -(static_cast<int64_t>(1) << (esize - 1u));
    const int64_t MAX_OUT = (static_cast<int64_t>(1) << (esize - 1u)) - 1;

    uint64_t scalar_raw = 0;
    std::memcpy(&scalar_raw,
                reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]) +
                    index * ebytes,
                ebytes);
    const int64_t scalar_s = static_cast<int64_t>(scalar_raw << sh) >> sh;

    bool qc_any = false;
    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* dn = reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < elements; ++e) {
            uint64_t op1_raw = 0;
            std::memcpy(&op1_raw, dn + e * ebytes, ebytes);
            const int64_t op1_s = static_cast<int64_t>(op1_raw << sh) >> sh;

            int64_t result;
            if (op1_s == MIN_OP && scalar_s == MIN_OP) {
                /* The only saturating case per A8.8.372 line 47921 /
                   A8.8.376 line 48319: 2*MIN*MIN >> esize = MAX+1 ⇒ MAX. */
                result = MAX_OUT;
                qc_any = true;
            } else {
                int64_t prod = 2 * (op1_s * scalar_s);
                if (is_rounding) {
                    prod += static_cast<int64_t>(1) << (esize - 1u);
                }
                result = prod >> esize;
            }

            const uint64_t result_raw = static_cast<uint64_t>(result);
            std::memcpy(res + e * ebytes, &result_raw, ebytes);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
    if (qc_any) {
        state->fpscr |= (1u << 27);
    }
}

void __cdecl ArmNeon2RegScalar::HandleScalarMulhSatHelper(ArmNeon2RegScalar* svc,
                                                          uint32_t op,
                                                          uint32_t d_idx, uint32_t n_idx,
                                                          uint32_t m_idx, uint32_t esize,
                                                          uint32_t index, uint32_t regs) {
    svc->HandleScalarMulhSat(op, d_idx, n_idx, m_idx, esize, index, regs);
}
