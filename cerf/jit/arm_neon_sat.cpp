#include "arm_neon_sat.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "arm_cpu.h"
#include "arm_vfp.h"

REGISTER_SERVICE(ArmNeonSat);

void ArmNeonSat::HandleSimd3SameSat(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                                    uint32_t m_idx, uint32_t esize, uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes   = esize / 8u;
    const uint32_t elements = 8u / ebytes;
    const uint32_t sh       = 64u - esize;
    bool saturated = false;

    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* dn = reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx + r]);
        const uint8_t* dm = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < elements; ++e) {
            uint64_t a = 0, b = 0;
            std::memcpy(&a, dn + e * ebytes, ebytes);
            std::memcpy(&b, dm + e * ebytes, ebytes);
            uint64_t s = 0;
            switch (op) {
                case kSatAddU: {
                    if (esize == 64u) {
                        const uint64_t sum = a + b;
                        if (sum < a) { s = ~0ull; saturated = true; }
                        else         { s = sum; }
                    } else {
                        const uint64_t max = (1ull << esize) - 1ull;
                        const uint64_t sum = a + b;
                        if (sum > max) { s = max; saturated = true; }
                        else           { s = sum; }
                    }
                    break;
                }
                case kSatSubU: {
                    if (a < b) { s = 0ull;  saturated = true; }
                    else       { s = a - b; }
                    break;
                }
                case kSatAddS: {
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    const int64_t sb = static_cast<int64_t>(b << sh) >> sh;
                    if (esize == 64u) {
                        const int64_t sum = static_cast<int64_t>(
                            static_cast<uint64_t>(sa) + static_cast<uint64_t>(sb));
                        /* signed add overflow: operands same sign, result
                           opposite sign. Removing this branch lets a 64-bit
                           overflowed sum silently bypass saturation. */
                        if (((sa ^ sum) & (sb ^ sum)) < 0) {
                            s = (sa < 0) ? static_cast<uint64_t>(INT64_MIN)
                                         : static_cast<uint64_t>(INT64_MAX);
                            saturated = true;
                        } else {
                            s = static_cast<uint64_t>(sum);
                        }
                    } else {
                        const int64_t sum = sa + sb;
                        const int64_t max = (1ll << (esize - 1u)) - 1;
                        const int64_t min = -(1ll << (esize - 1u));
                        if      (sum > max) { s = static_cast<uint64_t>(max); saturated = true; }
                        else if (sum < min) { s = static_cast<uint64_t>(min); saturated = true; }
                        else                  s = static_cast<uint64_t>(sum);
                    }
                    break;
                }
                /* VQSHL/VQRSHL (register, A8.8.379/377): data is `b` (D[m]),
                   shift source is `a` (D[n]) — operand reversal as in VSHL.
                   Right shift never saturates; the SatLeftShift* helpers
                   handle the shift>=0 saturating path. */
                case kSatShlU: {
                    const int32_t shift = static_cast<int8_t>(a & 0xFFu);
                    if (shift >= 0) {
                        s = SatLeftShiftU(b, shift, esize, saturated);
                    } else {
                        const uint32_t rs = static_cast<uint32_t>(-shift);
                        s = (rs >= 64u) ? 0ull : (b >> rs);
                    }
                    break;
                }
                case kSatShlS: {
                    const int32_t shift = static_cast<int8_t>(a & 0xFFu);
                    const int64_t sa = static_cast<int64_t>(b << sh) >> sh;
                    if (shift >= 0) {
                        s = SatLeftShiftS(sa, shift, esize, saturated);
                    } else {
                        uint32_t rs = static_cast<uint32_t>(-shift);
                        if (rs > 63u) rs = 63u;
                        s = static_cast<uint64_t>(sa >> rs);
                    }
                    break;
                }
                case kSatRshlU: {
                    const int32_t shift = static_cast<int8_t>(a & 0xFFu);
                    if (shift >= 0) {
                        s = SatLeftShiftU(b, shift, esize, saturated);
                    } else {
                        const uint32_t rs = static_cast<uint32_t>(-shift);
                        const uint64_t mainv = (rs >= 64u) ? 0ull : (b >> rs);
                        const uint64_t rbit  = (rs >= 65u) ? 0ull
                                                          : ((b >> (rs - 1u)) & 1ull);
                        s = mainv + rbit;
                    }
                    break;
                }
                case kSatRshlS: {
                    const int32_t shift = static_cast<int8_t>(a & 0xFFu);
                    const int64_t sa = static_cast<int64_t>(b << sh) >> sh;
                    if (shift >= 0) {
                        s = SatLeftShiftS(sa, shift, esize, saturated);
                    } else {
                        const uint32_t rs = static_cast<uint32_t>(-shift);
                        const int64_t  mainv = (rs >= 64u) ? (sa >> 63)
                                                          : (sa >> rs);
                        const uint64_t rbit  =
                            (rs >= 65u) ? (sa < 0 ? 1ull : 0ull)
                                        : ((static_cast<uint64_t>(sa) >> (rs - 1u)) & 1ull);
                        s = static_cast<uint64_t>(mainv + static_cast<int64_t>(rbit));
                    }
                    break;
                }
                case kSatSubS: {
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    const int64_t sb = static_cast<int64_t>(b << sh) >> sh;
                    if (esize == 64u) {
                        const int64_t diff = static_cast<int64_t>(
                            static_cast<uint64_t>(sa) - static_cast<uint64_t>(sb));
                        /* signed sub overflow: operands differ in sign AND
                           result differs in sign from minuend (sa). */
                        if (((sa ^ sb) & (sa ^ diff)) < 0) {
                            s = (sa < 0) ? static_cast<uint64_t>(INT64_MIN)
                                         : static_cast<uint64_t>(INT64_MAX);
                            saturated = true;
                        } else {
                            s = static_cast<uint64_t>(diff);
                        }
                    } else {
                        const int64_t diff = sa - sb;
                        const int64_t max = (1ll << (esize - 1u)) - 1;
                        const int64_t min = -(1ll << (esize - 1u));
                        if      (diff > max) { s = static_cast<uint64_t>(max); saturated = true; }
                        else if (diff < min) { s = static_cast<uint64_t>(min); saturated = true; }
                        else                   s = static_cast<uint64_t>(diff);
                    }
                    break;
                }
                default:
                    LOG(Caution, "HandleSimd3SameSat: unhandled op=%u\n", op);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            std::memcpy(res + e * ebytes, &s, ebytes);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }

    if (saturated) {
        state->fpscr |= ArmVfp::kFpscrQcMask;
    }
}

void __cdecl ArmNeonSat::HandleSimd3SameSatHelper(ArmNeonSat* sat, uint32_t op,
                                                  uint32_t d_idx, uint32_t n_idx,
                                                  uint32_t m_idx, uint32_t esize,
                                                  uint32_t regs) {
    sat->HandleSimd3SameSat(op, d_idx, n_idx, m_idx, esize, regs);
}

void ArmNeonSat::HandleShiftImmSat(uint32_t op, uint32_t d_idx, uint32_t m_idx,
                                   uint32_t esize, uint32_t shift_amount,
                                   uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes   = esize / 8u;
    const uint32_t elements = 8u / ebytes;
    const uint32_t sh       = 64u - esize;
    bool saturated = false;

    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* dm = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < elements; ++e) {
            uint64_t a = 0;
            std::memcpy(&a, dm + e * ebytes, ebytes);
            uint64_t s = 0;
            switch (op) {
                case kSatShlImmU:
                    s = SatLeftShiftU(a, static_cast<int32_t>(shift_amount),
                                      esize, saturated);
                    break;
                case kSatShlImmS: {
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    s = SatLeftShiftS(sa, static_cast<int32_t>(shift_amount),
                                      esize, saturated);
                    break;
                }
                /* VQSHLU: signed input, unsigned output. Negative inputs
                   saturate to 0; then the magnitude routes through the
                   unsigned-saturating helper for the upper clamp. */
                case kSatShlImmSU: {
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    if (sa < 0) {
                        s = 0ull;
                        saturated = true;
                    } else {
                        s = SatLeftShiftU(static_cast<uint64_t>(sa),
                                          static_cast<int32_t>(shift_amount),
                                          esize, saturated);
                    }
                    break;
                }
                default:
                    LOG(Caution, "HandleShiftImmSat: unhandled op=%u\n", op);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            std::memcpy(res + e * ebytes, &s, ebytes);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }

    if (saturated) {
        state->fpscr |= ArmVfp::kFpscrQcMask;
    }
}

void __cdecl ArmNeonSat::HandleShiftImmSatHelper(ArmNeonSat* sat, uint32_t op,
                                                 uint32_t d_idx, uint32_t m_idx,
                                                 uint32_t esize, uint32_t shift_amount,
                                                 uint32_t regs) {
    sat->HandleShiftImmSat(op, d_idx, m_idx, esize, shift_amount, regs);
}

void ArmNeonSat::HandleShiftImmNarrowSat(uint32_t op, uint32_t d_idx,
                                         uint32_t m_idx, uint32_t esize,
                                         uint32_t shift_amount) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t in_esize   = 2u * esize;
    const uint32_t out_ebytes = esize / 8u;
    const uint32_t in_ebytes  = 2u * out_ebytes;
    const uint32_t elements   = 8u / out_ebytes;
    const uint32_t sh         = (in_esize == 64u) ? 0u : (64u - in_esize);

    /* Output saturation bounds. esize ≤ 32 here (narrowing of source ≤ 64). */
    const uint64_t max_u_out = (1ull << esize) - 1ull;
    const int64_t  max_s_out = (1ll << (esize - 1u)) - 1;
    const int64_t  min_s_out = -(1ll << (esize - 1u));

    bool saturated = false;

    uint8_t src[16];
    std::memcpy(src,     &state->vfp_d[m_idx],     8);
    std::memcpy(src + 8, &state->vfp_d[m_idx + 1], 8);

    uint8_t res[8];
    for (uint32_t e = 0; e < elements; ++e) {
        uint64_t a = 0;
        std::memcpy(&a, src + e * in_ebytes, in_ebytes);
        uint64_t s = 0;
        /* shift_amount ∈ [1, esize_out] ⊆ [1, 32], so shift_amount and
           shift_amount-1 are both valid uint64/int64 shift counts. */
        switch (op) {
            /* VQSHRN.U: unsigned source, unsigned output, truncating. */
            case kSatShrnU: {
                const uint64_t shifted = a >> shift_amount;
                if (shifted > max_u_out) { s = max_u_out; saturated = true; }
                else                       s = shifted;
                break;
            }
            /* VQSHRN.S: signed source, signed output, truncating. */
            case kSatShrnS: {
                const int64_t sa = (in_esize == 64u)
                                       ? static_cast<int64_t>(a)
                                       : (static_cast<int64_t>(a << sh) >> sh);
                const int64_t shifted = sa >> shift_amount;
                if (shifted > max_s_out) {
                    s = static_cast<uint64_t>(max_s_out); saturated = true;
                } else if (shifted < min_s_out) {
                    s = static_cast<uint64_t>(min_s_out); saturated = true;
                } else {
                    s = static_cast<uint64_t>(shifted);
                }
                break;
            }
            /* VQSHRUN: signed source, unsigned output. Negative → 0;
               > max_u_out → max_u_out. */
            case kSatShrnSU: {
                const int64_t sa = (in_esize == 64u)
                                       ? static_cast<int64_t>(a)
                                       : (static_cast<int64_t>(a << sh) >> sh);
                const int64_t shifted = sa >> shift_amount;
                if (shifted < 0) {
                    s = 0ull; saturated = true;
                } else if (static_cast<uint64_t>(shifted) > max_u_out) {
                    s = max_u_out; saturated = true;
                } else {
                    s = static_cast<uint64_t>(shifted);
                }
                break;
            }
            /* VQRSHRN.U: unsigned source, unsigned output, rounding.
               Overflow-safe idiom: (a>>rs) + bit(rs-1) of a. */
            case kSatRShrnU: {
                const uint64_t mainv = a >> shift_amount;
                const uint64_t rbit  = (a >> (shift_amount - 1u)) & 1ull;
                const uint64_t shifted = mainv + rbit;
                if (shifted > max_u_out) { s = max_u_out; saturated = true; }
                else                       s = shifted;
                break;
            }
            /* VQRSHRN.S: signed source, signed output, rounding. */
            case kSatRShrnS: {
                const int64_t sa = (in_esize == 64u)
                                       ? static_cast<int64_t>(a)
                                       : (static_cast<int64_t>(a << sh) >> sh);
                const int64_t  mainv = sa >> shift_amount;
                const uint64_t rbit  = (static_cast<uint64_t>(sa) >> (shift_amount - 1u)) & 1ull;
                const int64_t shifted = mainv + static_cast<int64_t>(rbit);
                if (shifted > max_s_out) {
                    s = static_cast<uint64_t>(max_s_out); saturated = true;
                } else if (shifted < min_s_out) {
                    s = static_cast<uint64_t>(min_s_out); saturated = true;
                } else {
                    s = static_cast<uint64_t>(shifted);
                }
                break;
            }
            /* VQRSHRUN: signed source, unsigned output, rounding. */
            case kSatRShrnSU: {
                const int64_t sa = (in_esize == 64u)
                                       ? static_cast<int64_t>(a)
                                       : (static_cast<int64_t>(a << sh) >> sh);
                const int64_t  mainv = sa >> shift_amount;
                const uint64_t rbit  = (static_cast<uint64_t>(sa) >> (shift_amount - 1u)) & 1ull;
                const int64_t shifted = mainv + static_cast<int64_t>(rbit);
                if (shifted < 0) {
                    s = 0ull; saturated = true;
                } else if (static_cast<uint64_t>(shifted) > max_u_out) {
                    s = max_u_out; saturated = true;
                } else {
                    s = static_cast<uint64_t>(shifted);
                }
                break;
            }
            default:
                LOG(Caution, "HandleShiftImmNarrowSat: unhandled op=%u\n", op);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        std::memcpy(res + e * out_ebytes, &s, out_ebytes);
    }
    std::memcpy(&state->vfp_d[d_idx], res, 8);

    if (saturated) {
        state->fpscr |= ArmVfp::kFpscrQcMask;
    }
}

void __cdecl ArmNeonSat::HandleShiftImmNarrowSatHelper(ArmNeonSat* sat, uint32_t op,
                                                       uint32_t d_idx, uint32_t m_idx,
                                                       uint32_t esize, uint32_t shift_amount) {
    sat->HandleShiftImmNarrowSat(op, d_idx, m_idx, esize, shift_amount);
}

uint64_t ArmNeonSat::SatLeftShiftU(uint64_t value, int32_t shift,
                                   uint32_t esize, bool& saturated) {
    if (shift == 0) return value;
    const uint64_t max_u = (esize == 64u) ? ~0ull : ((1ull << esize) - 1ull);
    if (static_cast<uint32_t>(shift) >= esize) {
        if (value != 0u) { saturated = true; return max_u; }
        return 0ull;
    }
    /* shift in (0, esize) <= (0, 64): both shifts well-defined. */
    const uint32_t headroom = esize - static_cast<uint32_t>(shift);
    if ((value >> headroom) != 0u) {
        saturated = true;
        return max_u;
    }
    return value << shift;
}

uint64_t ArmNeonSat::SatLeftShiftS(int64_t value, int32_t shift,
                                   uint32_t esize, bool& saturated) {
    if (shift == 0) return static_cast<uint64_t>(value);
    if (static_cast<uint32_t>(shift) >= esize) {
        if (value > 0) {
            saturated = true;
            return (esize == 64u) ? static_cast<uint64_t>(INT64_MAX)
                                  : static_cast<uint64_t>((1ll << (esize - 1u)) - 1);
        }
        if (value < 0) {
            saturated = true;
            return (esize == 64u) ? static_cast<uint64_t>(INT64_MIN)
                                  : static_cast<uint64_t>(-(1ll << (esize - 1u)));
        }
        return 0ull;
    }
    /* shift in (0, esize). Cast to uint64 before shifting — signed-left of
       negative is UB. For esize==64, use round-trip arithmetic-shift check
       to detect any overflow past the int64 (= esize) signed range. */
    if (esize == 64u) {
        const int64_t shifted = static_cast<int64_t>(
            static_cast<uint64_t>(value) << static_cast<uint32_t>(shift));
        if ((shifted >> shift) != value) {
            saturated = true;
            return (value > 0) ? static_cast<uint64_t>(INT64_MAX)
                               : static_cast<uint64_t>(INT64_MIN);
        }
        return static_cast<uint64_t>(shifted);
    }
    const int64_t shifted = static_cast<int64_t>(
        static_cast<uint64_t>(value) << static_cast<uint32_t>(shift));
    const int64_t max_s = (1ll << (esize - 1u)) - 1;
    const int64_t min_s = -(1ll << (esize - 1u));
    if (shifted > max_s) { saturated = true; return static_cast<uint64_t>(max_s); }
    if (shifted < min_s) { saturated = true; return static_cast<uint64_t>(min_s); }
    return static_cast<uint64_t>(shifted);
}
