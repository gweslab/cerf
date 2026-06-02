#include "arm_neon_shift_imm.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeonShiftImm);

void ArmNeonShiftImm::HandleShiftImm(uint32_t op, uint32_t d_idx, uint32_t m_idx,
                                     uint32_t esize, uint32_t shift_amount,
                                     uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes   = esize / 8u;
    const uint32_t elements = 8u / ebytes;
    const uint32_t sh       = 64u - esize;

    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* dm = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx + r]);
        /* dd captured pre-loop; accumulate cases (VSRA/VRSRA) read it. Final
           write goes to res[] then memcpy'd back, so d==m aliasing is safe. */
        const uint8_t* dd = reinterpret_cast<const uint8_t*>(&state->vfp_d[d_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < elements; ++e) {
            uint64_t a = 0;
            std::memcpy(&a, dm + e * ebytes, ebytes);
            uint64_t s = 0;
            switch (op) {
                case kSiShrU: {
                    /* shift_amount in [1, esize] (decoder enforces);
                       guard for esize=64,shift=64 case where a>>64 is UB. */
                    s = (shift_amount >= 64u) ? 0ull : (a >> shift_amount);
                    break;
                }
                case kSiShrS: {
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    /* arithmetic >> by >=64 is UB; sh-amount=64 (esize=64,imm=64)
                       saturates at >>63 which already fills the sign. */
                    uint32_t rs = shift_amount;
                    if (rs > 63u) rs = 63u;
                    s = static_cast<uint64_t>(sa >> rs);
                    break;
                }
                /* VSHL imm: shift_amount in [0, esize-1] <= [0, 63], so a<<shift
                   is always defined; the ebytes memcpy masks to esize. */
                case kSiShl:
                    s = a << shift_amount;
                    break;
                /* VRSHR rounding: same overflow-safe idiom as VRSHL right shift —
                   main = a>>rs (clamp/zero at >=64), rbit = bit (rs-1) of a. */
                case kSiRshrU: {
                    const uint32_t rs = shift_amount;
                    const uint64_t mainv = (rs >= 64u) ? 0ull : (a >> rs);
                    const uint64_t rbit  = (rs >= 65u) ? 0ull
                                                      : ((a >> (rs - 1u)) & 1ull);
                    s = mainv + rbit;
                    break;
                }
                case kSiRshrS: {
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    const uint32_t rs = shift_amount;
                    const int64_t  mainv = (rs >= 64u) ? (sa >> 63) : (sa >> rs);
                    const uint64_t rbit  = (rs >= 65u) ? (sa < 0 ? 1ull : 0ull)
                                                      : ((static_cast<uint64_t>(sa) >> (rs - 1u)) & 1ull);
                    s = static_cast<uint64_t>(mainv + static_cast<int64_t>(rbit));
                    break;
                }
                /* VSRA: d = d_old + (a >> shift). Wrap mod 2^esize via store. */
                case kSiSraU: {
                    uint64_t d_val = 0;
                    std::memcpy(&d_val, dd + e * ebytes, ebytes);
                    const uint64_t shifted = (shift_amount >= 64u)
                                                 ? 0ull : (a >> shift_amount);
                    s = d_val + shifted;
                    break;
                }
                case kSiSraS: {
                    uint64_t d_val = 0;
                    std::memcpy(&d_val, dd + e * ebytes, ebytes);
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    uint32_t rs = shift_amount;
                    if (rs > 63u) rs = 63u;
                    s = d_val + static_cast<uint64_t>(sa >> rs);
                    break;
                }
                /* VRSRA: d = d_old + rounded_right_shift(a, shift). */
                case kSiRsraU: {
                    uint64_t d_val = 0;
                    std::memcpy(&d_val, dd + e * ebytes, ebytes);
                    const uint32_t rs = shift_amount;
                    const uint64_t mainv = (rs >= 64u) ? 0ull : (a >> rs);
                    const uint64_t rbit  = (rs >= 65u) ? 0ull
                                                      : ((a >> (rs - 1u)) & 1ull);
                    s = d_val + mainv + rbit;
                    break;
                }
                case kSiRsraS: {
                    uint64_t d_val = 0;
                    std::memcpy(&d_val, dd + e * ebytes, ebytes);
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    const uint32_t rs = shift_amount;
                    const int64_t  mainv = (rs >= 64u) ? (sa >> 63)
                                                      : (sa >> rs);
                    const uint64_t rbit  =
                        (rs >= 65u) ? (sa < 0 ? 1ull : 0ull)
                                    : ((static_cast<uint64_t>(sa) >> (rs - 1u)) & 1ull);
                    const int64_t shifted = mainv + static_cast<int64_t>(rbit);
                    s = d_val + static_cast<uint64_t>(shifted);
                    break;
                }
                /* VSRI: shift m right; preserve top `shift_amount` bits of d.
                   shift_amount==esize fully clears m → result = d (guard for
                   a>>64 UB at esize=64,shift=64). */
                case kSiSri: {
                    uint64_t d_val = 0;
                    std::memcpy(&d_val, dd + e * ebytes, ebytes);
                    if (shift_amount >= esize) {
                        s = d_val;
                    } else {
                        const uint64_t shifted_m = a >> shift_amount;
                        const uint64_t keep_mask =
                            ~((1ull << (esize - shift_amount)) - 1ull);
                        s = (d_val & keep_mask) | shifted_m;
                    }
                    break;
                }
                /* VSLI: shift m left; preserve bottom `shift_amount` bits of d.
                   shift_amount in [0, esize-1] so the left shift is always
                   defined; shift_amount==0 produces (m | (d & 0)) = m. */
                case kSiSli: {
                    uint64_t d_val = 0;
                    std::memcpy(&d_val, dd + e * ebytes, ebytes);
                    const uint64_t shifted_m = a << shift_amount;
                    const uint64_t keep_mask = (shift_amount == 0u)
                                                   ? 0ull
                                                   : ((1ull << shift_amount) - 1ull);
                    s = (d_val & keep_mask) | shifted_m;
                    break;
                }
                default:
                    LOG(Caution, "HandleShiftImm: unhandled op=%u\n", op);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            std::memcpy(res + e * ebytes, &s, ebytes);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeonShiftImm::HandleShiftImmHelper(ArmNeonShiftImm* svc, uint32_t op,
                                                   uint32_t d_idx, uint32_t m_idx,
                                                   uint32_t esize, uint32_t shift_amount,
                                                   uint32_t regs) {
    svc->HandleShiftImm(op, d_idx, m_idx, esize, shift_amount, regs);
}

void ArmNeonShiftImm::HandleShiftImmNarrow(uint32_t op, uint32_t d_idx,
                                           uint32_t m_idx, uint32_t esize,
                                           uint32_t shift_amount) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t out_ebytes = esize / 8u;
    const uint32_t in_ebytes  = 2u * out_ebytes;
    const uint32_t elements   = 8u / out_ebytes;

    /* Source Q register = D[m_idx]:D[m_idx+1] (16 bytes). */
    uint8_t src[16];
    std::memcpy(src,     &state->vfp_d[m_idx],     8);
    std::memcpy(src + 8, &state->vfp_d[m_idx + 1], 8);

    uint8_t res[8];
    for (uint32_t e = 0; e < elements; ++e) {
        uint64_t a = 0;
        std::memcpy(&a, src + e * in_ebytes, in_ebytes);
        uint64_t s = 0;
        switch (op) {
            case kSiShrn:
                /* shift_amount in [1, esize] (esize_out ≤ 32) < 64, so no UB. */
                s = a >> shift_amount;
                break;
            case kSiRshrn: {
                /* Rounding: result = (a >> rs) + bit (rs-1) of a. Same
                   overflow-safe idiom as VRSHR. rs ∈ [1, esize_out] ≤ 32,
                   so rs and rs-1 are both valid uint64 shift counts. */
                const uint32_t rs = shift_amount;
                const uint64_t mainv = a >> rs;
                const uint64_t rbit  = (a >> (rs - 1u)) & 1ull;
                s = mainv + rbit;
                break;
            }
            default:
                LOG(Caution, "HandleShiftImmNarrow: unhandled op=%u\n", op);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        std::memcpy(res + e * out_ebytes, &s, out_ebytes);
    }
    std::memcpy(&state->vfp_d[d_idx], res, 8);
}

void __cdecl ArmNeonShiftImm::HandleShiftImmNarrowHelper(ArmNeonShiftImm* svc, uint32_t op,
                                                         uint32_t d_idx, uint32_t m_idx,
                                                         uint32_t esize, uint32_t shift_amount) {
    svc->HandleShiftImmNarrow(op, d_idx, m_idx, esize, shift_amount);
}

void ArmNeonShiftImm::HandleShiftImmWiden(uint32_t op, uint32_t d_idx,
                                          uint32_t m_idx, uint32_t esize,
                                          uint32_t shift_amount) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t in_ebytes  = esize / 8u;
    const uint32_t out_ebytes = 2u * in_ebytes;
    const uint32_t elements   = 8u / in_ebytes;
    const uint32_t sh         = 64u - esize;

    const uint8_t* dm = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]);

    uint8_t res[16];
    for (uint32_t e = 0; e < elements; ++e) {
        uint64_t a = 0;
        std::memcpy(&a, dm + e * in_ebytes, in_ebytes);
        uint64_t s = 0;
        switch (op) {
            case kSiShllS: {
                /* Sign-extend from esize bits, then shift left. esize ≤ 32 ⇒
                   sh ≥ 32, so a<<sh and >>sh are defined. shift_amount in
                   [0, esize-1] ≤ 31, so the left shift is defined. */
                const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                s = static_cast<uint64_t>(sa) << shift_amount;
                break;
            }
            case kSiShllU: {
                /* memcpy of in_ebytes from low end already zero-pads top. */
                s = a << shift_amount;
                break;
            }
            default:
                LOG(Caution, "HandleShiftImmWiden: unhandled op=%u\n", op);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        std::memcpy(res + e * out_ebytes, &s, out_ebytes);
    }
    std::memcpy(&state->vfp_d[d_idx],     res,     8);
    std::memcpy(&state->vfp_d[d_idx + 1], res + 8, 8);
}

void __cdecl ArmNeonShiftImm::HandleShiftImmWidenHelper(ArmNeonShiftImm* svc, uint32_t op,
                                                        uint32_t d_idx, uint32_t m_idx,
                                                        uint32_t esize, uint32_t shift_amount) {
    svc->HandleShiftImmWiden(op, d_idx, m_idx, esize, shift_amount);
}
