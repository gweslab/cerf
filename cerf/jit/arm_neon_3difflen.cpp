#include "arm_neon_3difflen.h"

#include <cstdint>
#include <cstring>
#include <limits>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeon3DiffLen);

void ArmNeon3DiffLen::HandleAddSubLW(uint32_t op, uint32_t d_idx,
                                     uint32_t n_idx, uint32_t m_idx,
                                     uint32_t esize, uint32_t u) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t in_ebytes  = esize / 8u;
    const uint32_t out_ebytes = 2u * in_ebytes;
    const uint32_t elements   = 8u / in_ebytes;
    const uint32_t sh         = 64u - esize;
    const uint32_t out_sh     = 64u - 2u * esize;
    const bool is_sub  = (op == kDlSubLong) || (op == kDlSubWide);
    const bool is_wide = (op == kDlAddWide) || (op == kDlSubWide);
    const bool unsigned_op = (u != 0u);

    uint8_t src1[16] = {0};
    if (is_wide) {
        std::memcpy(src1,     &state->vfp_d[n_idx],     8);
        std::memcpy(src1 + 8, &state->vfp_d[n_idx + 1], 8);
    } else {
        std::memcpy(src1, &state->vfp_d[n_idx], 8);
    }
    const uint8_t* dm = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]);

    uint8_t res[16];
    for (uint32_t e = 0; e < elements; ++e) {
        uint64_t op1_raw = 0;
        uint64_t op2_raw = 0;
        if (is_wide) {
            std::memcpy(&op1_raw, src1 + e * out_ebytes, out_ebytes);
        } else {
            std::memcpy(&op1_raw, src1 + e * in_ebytes, in_ebytes);
        }
        std::memcpy(&op2_raw, dm + e * in_ebytes, in_ebytes);

        uint64_t s = 0;
        if (unsigned_op) {
            s = is_sub ? (op1_raw - op2_raw) : (op1_raw + op2_raw);
        } else {
            /* Sign-extend each operand to int64; sum/diff in uint64 to get
               defined wraparound (signed overflow at esize=32 wide is UB). */
            const int64_t op1_signed = is_wide
                ? (static_cast<int64_t>(op1_raw << out_sh) >> out_sh)
                : (static_cast<int64_t>(op1_raw << sh)     >> sh);
            const int64_t op2_signed = static_cast<int64_t>(op2_raw << sh) >> sh;
            const uint64_t u1 = static_cast<uint64_t>(op1_signed);
            const uint64_t u2 = static_cast<uint64_t>(op2_signed);
            s = is_sub ? (u1 - u2) : (u1 + u2);
        }
        std::memcpy(res + e * out_ebytes, &s, out_ebytes);
    }
    std::memcpy(&state->vfp_d[d_idx],     res,     8);
    std::memcpy(&state->vfp_d[d_idx + 1], res + 8, 8);
}

void __cdecl ArmNeon3DiffLen::HandleAddSubLWHelper(ArmNeon3DiffLen* svc, uint32_t op,
                                                   uint32_t d_idx, uint32_t n_idx,
                                                   uint32_t m_idx, uint32_t esize,
                                                   uint32_t u) {
    svc->HandleAddSubLW(op, d_idx, n_idx, m_idx, esize, u);
}

void ArmNeon3DiffLen::HandleAddSubHN(uint32_t op, uint32_t d_idx,
                                     uint32_t n_idx, uint32_t m_idx,
                                     uint32_t esize) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t in_ebytes  = 2u * (esize / 8u);
    const uint32_t out_ebytes = esize / 8u;
    const uint32_t elements   = 8u / out_ebytes;
    const bool is_sub   = (op == kDlSubhn) || (op == kDlRsubhn);
    const bool is_round = (op == kDlRaddhn) || (op == kDlRsubhn);

    uint8_t src_n[16];
    uint8_t src_m[16];
    std::memcpy(src_n,     &state->vfp_d[n_idx],     8);
    std::memcpy(src_n + 8, &state->vfp_d[n_idx + 1], 8);
    std::memcpy(src_m,     &state->vfp_d[m_idx],     8);
    std::memcpy(src_m + 8, &state->vfp_d[m_idx + 1], 8);

    uint8_t res[8];
    for (uint32_t e = 0; e < elements; ++e) {
        uint64_t op1 = 0;
        uint64_t op2 = 0;
        std::memcpy(&op1, src_n + e * in_ebytes, in_ebytes);
        std::memcpy(&op2, src_m + e * in_ebytes, in_ebytes);

        uint64_t result = is_sub ? (op1 - op2) : (op1 + op2);
        if (is_round) {
            result += 1ull << (esize - 1u);
        }
        const uint64_t high_half = result >> esize;
        std::memcpy(res + e * out_ebytes, &high_half, out_ebytes);
    }
    std::memcpy(&state->vfp_d[d_idx], res, 8);
}

void __cdecl ArmNeon3DiffLen::HandleAddSubHNHelper(ArmNeon3DiffLen* svc, uint32_t op,
                                                   uint32_t d_idx, uint32_t n_idx,
                                                   uint32_t m_idx, uint32_t esize) {
    svc->HandleAddSubHN(op, d_idx, n_idx, m_idx, esize);
}

void ArmNeon3DiffLen::HandleAbsDiffLong(uint32_t op, uint32_t d_idx,
                                        uint32_t n_idx, uint32_t m_idx,
                                        uint32_t esize) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t in_ebytes  = esize / 8u;
    const uint32_t out_ebytes = 2u * in_ebytes;
    const uint32_t elements   = 8u / in_ebytes;
    const uint32_t sh         = 64u - esize;
    const bool is_accum    = (op == kDlAbalS) || (op == kDlAbalU);
    const bool is_unsigned = (op == kDlAbdlU) || (op == kDlAbalU);

    const uint8_t* dn = reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx]);
    const uint8_t* dm = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]);

    uint8_t dd[16] = {0};
    if (is_accum) {
        std::memcpy(dd,     &state->vfp_d[d_idx],     8);
        std::memcpy(dd + 8, &state->vfp_d[d_idx + 1], 8);
    }

    uint8_t res[16];
    for (uint32_t e = 0; e < elements; ++e) {
        uint64_t op1_raw = 0;
        uint64_t op2_raw = 0;
        std::memcpy(&op1_raw, dn + e * in_ebytes, in_ebytes);
        std::memcpy(&op2_raw, dm + e * in_ebytes, in_ebytes);

        uint64_t absdiff;
        if (is_unsigned) {
            absdiff = (op1_raw >= op2_raw) ? (op1_raw - op2_raw)
                                           : (op2_raw - op1_raw);
        } else {
            const int64_t op1_s = static_cast<int64_t>(op1_raw << sh) >> sh;
            const int64_t op2_s = static_cast<int64_t>(op2_raw << sh) >> sh;
            const int64_t diff = op1_s - op2_s;
            absdiff = static_cast<uint64_t>(diff < 0 ? -diff : diff);
        }

        uint64_t s = absdiff;
        if (is_accum) {
            uint64_t accum = 0;
            std::memcpy(&accum, dd + e * out_ebytes, out_ebytes);
            s = accum + absdiff;
        }
        std::memcpy(res + e * out_ebytes, &s, out_ebytes);
    }
    std::memcpy(&state->vfp_d[d_idx],     res,     8);
    std::memcpy(&state->vfp_d[d_idx + 1], res + 8, 8);
}

void __cdecl ArmNeon3DiffLen::HandleAbsDiffLongHelper(ArmNeon3DiffLen* svc, uint32_t op,
                                                      uint32_t d_idx, uint32_t n_idx,
                                                      uint32_t m_idx, uint32_t esize) {
    svc->HandleAbsDiffLong(op, d_idx, n_idx, m_idx, esize);
}

void ArmNeon3DiffLen::HandleMulLong(uint32_t op, uint32_t d_idx,
                                    uint32_t n_idx, uint32_t m_idx,
                                    uint32_t esize) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t in_ebytes  = esize / 8u;
    const uint32_t out_ebytes = 2u * in_ebytes;
    const uint32_t elements   = 8u / in_ebytes;
    const uint32_t sh         = 64u - esize;
    const bool is_unsigned = (op == kDlMlalU) || (op == kDlMlslU) ||
                             (op == kDlMullIntU);
    const bool is_subtract = (op == kDlMlslS) || (op == kDlMlslU);
    const bool is_accum    = (op == kDlMlalS) || (op == kDlMlalU) ||
                             (op == kDlMlslS) || (op == kDlMlslU);
    const bool is_poly     = (op == kDlMullPoly);

    const uint8_t* dn = reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx]);
    const uint8_t* dm = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]);

    uint8_t dd[16] = {0};
    if (is_accum) {
        std::memcpy(dd,     &state->vfp_d[d_idx],     8);
        std::memcpy(dd + 8, &state->vfp_d[d_idx + 1], 8);
    }

    uint8_t res[16];
    for (uint32_t e = 0; e < elements; ++e) {
        uint64_t op1_raw = 0;
        uint64_t op2_raw = 0;
        std::memcpy(&op1_raw, dn + e * in_ebytes, in_ebytes);
        std::memcpy(&op2_raw, dm + e * in_ebytes, in_ebytes);

        uint64_t product;
        if (is_poly) {
            /* place_fn enforces esize=8 so op1_raw/op2_raw are in [0,255]
               and the inner loop walks bits 0..7 of op1. */
            product = 0;
            for (uint32_t i = 0; i < 8u; ++i) {
                if ((op1_raw >> i) & 1u) {
                    product ^= op2_raw << i;
                }
            }
        } else if (is_unsigned) {
            product = op1_raw * op2_raw;
        } else {
            const int64_t op1_s = static_cast<int64_t>(op1_raw << sh) >> sh;
            const int64_t op2_s = static_cast<int64_t>(op2_raw << sh) >> sh;
            product = static_cast<uint64_t>(op1_s * op2_s);
        }

        uint64_t s;
        if (is_accum) {
            uint64_t accum = 0;
            std::memcpy(&accum, dd + e * out_ebytes, out_ebytes);
            s = is_subtract ? (accum - product) : (accum + product);
        } else {
            s = product;
        }
        std::memcpy(res + e * out_ebytes, &s, out_ebytes);
    }
    std::memcpy(&state->vfp_d[d_idx],     res,     8);
    std::memcpy(&state->vfp_d[d_idx + 1], res + 8, 8);
}

void __cdecl ArmNeon3DiffLen::HandleMulLongHelper(ArmNeon3DiffLen* svc, uint32_t op,
                                                  uint32_t d_idx, uint32_t n_idx,
                                                  uint32_t m_idx, uint32_t esize) {
    svc->HandleMulLong(op, d_idx, n_idx, m_idx, esize);
}

void ArmNeon3DiffLen::HandleMulLongSat(uint32_t op, uint32_t d_idx,
                                       uint32_t n_idx, uint32_t m_idx,
                                       uint32_t esize) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t in_ebytes  = esize / 8u;
    const uint32_t out_ebytes = 2u * in_ebytes;
    const uint32_t elements   = 8u / in_ebytes;
    const uint32_t sh         = 64u - esize;
    const uint32_t out_bits   = 2u * esize;
    const bool is_accum    = (op == kDlVqdmlal) || (op == kDlVqdmlsl);
    const bool is_subtract = (op == kDlVqdmlsl);
    const int64_t  MIN_OP    = -(static_cast<int64_t>(1) << (esize - 1u));
    const int64_t  MAX_OUT   = (out_bits == 64u)
                                   ? std::numeric_limits<int64_t>::max()
                                   : ((static_cast<int64_t>(1) << (out_bits - 1u)) - 1);
    const int64_t  MIN_OUT   = (out_bits == 64u)
                                   ? std::numeric_limits<int64_t>::min()
                                   : (-(static_cast<int64_t>(1) << (out_bits - 1u)));
    const uint64_t sign_bit  = static_cast<uint64_t>(1) << (out_bits - 1u);

    const uint8_t* dn = reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx]);
    const uint8_t* dm = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]);

    uint8_t dd[16] = {0};
    if (is_accum) {
        std::memcpy(dd,     &state->vfp_d[d_idx],     8);
        std::memcpy(dd + 8, &state->vfp_d[d_idx + 1], 8);
    }

    uint8_t res[16];
    bool qc_any = false;
    for (uint32_t e = 0; e < elements; ++e) {
        uint64_t op1_raw = 0;
        uint64_t op2_raw = 0;
        std::memcpy(&op1_raw, dn + e * in_ebytes, in_ebytes);
        std::memcpy(&op2_raw, dm + e * in_ebytes, in_ebytes);
        const int64_t op1_s = static_cast<int64_t>(op1_raw << sh) >> sh;
        const int64_t op2_s = static_cast<int64_t>(op2_raw << sh) >> sh;

        int64_t product;
        bool sat1 = false;
        if (op1_s == MIN_OP && op2_s == MIN_OP) {
            /* 2*MIN*MIN = 2^(2*esize-1) overflows the signed 2*esize range
               by exactly one — saturate to MAX. */
            product = MAX_OUT;
            sat1 = true;
        } else {
            product = 2 * (op1_s * op2_s);
        }

        int64_t final_result;
        bool sat2 = false;
        if (is_accum) {
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
        } else {
            final_result = product;
        }

        if (sat1 || sat2) {
            qc_any = true;
        }

        const uint64_t result_raw = static_cast<uint64_t>(final_result);
        std::memcpy(res + e * out_ebytes, &result_raw, out_ebytes);
    }
    if (qc_any) {
        /* FPSCR.QC is sticky (A2.8.2): set on saturation, cleared only by
           explicit MSR write to FPSCR. */
        state->fpscr |= (1u << 27);
    }
    std::memcpy(&state->vfp_d[d_idx],     res,     8);
    std::memcpy(&state->vfp_d[d_idx + 1], res + 8, 8);
}

void __cdecl ArmNeon3DiffLen::HandleMulLongSatHelper(ArmNeon3DiffLen* svc, uint32_t op,
                                                     uint32_t d_idx, uint32_t n_idx,
                                                     uint32_t m_idx, uint32_t esize) {
    svc->HandleMulLongSat(op, d_idx, n_idx, m_idx, esize);
}
