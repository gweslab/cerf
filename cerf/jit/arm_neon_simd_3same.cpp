#include "arm_neon_simd_3same.h"

#include <cstdint>
#include <cstring>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "arm_cpu.h"

REGISTER_SERVICE(ArmNeonSimd3Same);

void ArmNeonSimd3Same::HandleSimd3Same(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                                       uint32_t m_idx, uint32_t esize, uint32_t regs) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes   = esize / 8u;
    const uint32_t elements = 8u / ebytes;
    for (uint32_t r = 0; r < regs; ++r) {
        const uint8_t* dn = reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx + r]);
        const uint8_t* dm = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx + r]);
        const uint8_t* dd = reinterpret_cast<const uint8_t*>(&state->vfp_d[d_idx + r]);
        uint8_t res[8];
        for (uint32_t e = 0; e < elements; ++e) {
            uint64_t a = 0, b = 0;
            std::memcpy(&a, dn + e * ebytes, ebytes);
            std::memcpy(&b, dm + e * ebytes, ebytes);
            uint64_t s = 0;
            /* Logical ops are bit-wise: per-element (any esize) equals the
               whole-register result, so they share this loop. */
            switch (op) {
                case kS3Add: s = a + b;  break;       /* mod 2^esize via store */
                case kS3Sub: s = a - b;  break;
                case kS3And: s = a & b;  break;
                case kS3Bic: s = a & ~b; break;
                case kS3Orr: s = a | b;  break;
                case kS3Orn: s = a | ~b; break;
                case kS3Eor: s = a ^ b;  break;
                /* VMUL integer (A8.8.350, op=0): result low esize bits =
                   (a*b) mod 2^esize. Signedness don't-care (A8.8.350 line
                   45829). size==11 UND'd by the place_fn. */
                case kS3Mul: s = a * b;  break;
                /* VMUL.P8 polynomial (A8.8.350, op=1): carry-less multiply
                   over GF(2). place_fn enforces esize=8, so a/b are in
                   [0,255] and the inner loop walks bits 0..7 of a. result
                   is up to 15 bits; memcpy of ebytes=1 takes the low 8. */
                case kS3MulP: {
                    uint64_t result = 0u;
                    for (uint32_t i = 0; i < 8u; ++i) {
                        if ((a >> i) & 1u) {
                            result ^= b << i;
                        }
                    }
                    s = result;
                    break;
                }
                /* VBSL: D[d] = (D[n] & D[d]) | (D[m] & ~D[d]) (A8.8.290). */
                case kS3Bsl: {
                    uint64_t c = 0;
                    std::memcpy(&c, dd + e * ebytes, ebytes);
                    s = (a & c) | (b & ~c);
                    break;
                }
                /* VBIT: D[d] = (D[n] & D[m]) | (D[d] & ~D[m]) (A8.8.290). */
                case kS3Bit: {
                    uint64_t c = 0;
                    std::memcpy(&c, dd + e * ebytes, ebytes);
                    s = (a & b) | (c & ~b);
                    break;
                }
                /* VBIF: D[d] = (D[d] & D[m]) | (D[n] & ~D[m]) (A8.8.290). */
                case kS3Bif: {
                    uint64_t c = 0;
                    std::memcpy(&c, dd + e * ebytes, ebytes);
                    s = (c & b) | (a & ~b);
                    break;
                }
                /* Compares: a/b are zero-extended ebytes-wide values; the
                   result is all-ones across the element on true. memcpy of
                   ebytes from ~0ull writes exactly ebytes of 0xFF. size==11
                   is rejected at decode, so esize is 8/16/32 (shift < 64). */
                case kS3Ceq:  s = (a == b)        ? ~0ull : 0ull; break;
                case kS3Tst:  s = ((a & b) != 0u) ? ~0ull : 0ull; break;
                case kS3CgtU: s = (a >  b)        ? ~0ull : 0ull; break;
                case kS3CgeU: s = (a >= b)        ? ~0ull : 0ull; break;
                case kS3CgtS: {
                    const uint32_t sh = 64u - esize;
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    const int64_t sb = static_cast<int64_t>(b << sh) >> sh;
                    s = (sa > sb) ? ~0ull : 0ull;
                    break;
                }
                case kS3CgeS: {
                    const uint32_t sh = 64u - esize;
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    const int64_t sb = static_cast<int64_t>(b << sh) >> sh;
                    s = (sa >= sb) ? ~0ull : 0ull;
                    break;
                }
                /* VMAX/VMIN: store the chosen original element (a or b); the
                   store's memcpy of ebytes keeps exactly that element. */
                case kS3MaxU: s = (a >= b) ? a : b; break;
                case kS3MinU: s = (a <= b) ? a : b; break;
                case kS3MaxS: {
                    const uint32_t sh = 64u - esize;
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    const int64_t sb = static_cast<int64_t>(b << sh) >> sh;
                    s = (sa >= sb) ? a : b;
                    break;
                }
                case kS3MinS: {
                    const uint32_t sh = 64u - esize;
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    const int64_t sb = static_cast<int64_t>(b << sh) >> sh;
                    s = (sa <= sb) ? a : b;
                    break;
                }
                /* Halving add/sub + rounding halving add: result<esize:1> =
                   (op1 +/- op2 [+1]) >> 1. Unsigned operands wrap in uint64
                   (intended for VHSUB a<b); the >>1 + ebytes memcpy take the
                   low esize bits, matching result<esize:1>. */
                case kS3HaddU:  s = (a + b)      >> 1; break;
                case kS3HsubU:  s = (a - b)      >> 1; break;
                case kS3RhaddU: s = (a + b + 1u) >> 1; break;
                case kS3HaddS: {
                    const uint32_t sh = 64u - esize;
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    const int64_t sb = static_cast<int64_t>(b << sh) >> sh;
                    s = static_cast<uint64_t>((sa + sb) >> 1);
                    break;
                }
                case kS3HsubS: {
                    const uint32_t sh = 64u - esize;
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    const int64_t sb = static_cast<int64_t>(b << sh) >> sh;
                    s = static_cast<uint64_t>((sa - sb) >> 1);
                    break;
                }
                case kS3RhaddS: {
                    const uint32_t sh = 64u - esize;
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    const int64_t sb = static_cast<int64_t>(b << sh) >> sh;
                    s = static_cast<uint64_t>((sa + sb + 1) >> 1);
                    break;
                }
                /* VABD: |op1-op2| in low esize bits (always fits, max
                   2^esize-1). Unsigned subtracts the smaller from the
                   larger; signed takes abs of the sign-extended diff. */
                case kS3AbdU: s = (a >= b) ? (a - b) : (b - a); break;
                case kS3AbdS: {
                    const uint32_t sh = 64u - esize;
                    const int64_t sa = static_cast<int64_t>(a << sh) >> sh;
                    const int64_t sb = static_cast<int64_t>(b << sh) >> sh;
                    const int64_t diff = sa - sb;
                    s = static_cast<uint64_t>(diff < 0 ? -diff : diff);
                    break;
                }
                /* VSHL (register): data is D[m] (=b); shift is the signed low
                   byte of D[n] (=a) — operands reversed vs the symmetric ops.
                   The guards are load-bearing: a C++ shift by >= operand width
                   (the byte ranges to 127) is UB. */
                case kS3ShlU: {
                    const int32_t shift = static_cast<int8_t>(a & 0xFFu);
                    if (shift >= 0) {
                        s = (shift >= 64) ? 0ull : (b << shift);
                    } else {
                        const uint32_t rs = static_cast<uint32_t>(-shift);
                        s = (rs >= 64u) ? 0ull : (b >> rs);  /* logical */
                    }
                    break;
                }
                case kS3ShlS: {
                    const int32_t shift = static_cast<int8_t>(a & 0xFFu);
                    const uint32_t sh = 64u - esize;
                    const int64_t val = static_cast<int64_t>(b << sh) >> sh;
                    if (shift >= 0) {
                        s = (shift >= 64) ? 0ull
                                          : (static_cast<uint64_t>(val) << shift);
                    } else {
                        uint32_t rs = static_cast<uint32_t>(-shift);
                        if (rs > 63u) rs = 63u;  /* arith >> by >=64 is UB */
                        s = static_cast<uint64_t>(val >> rs);  /* arithmetic */
                    }
                    break;
                }
                /* VRSHL (register): same operand reversal as VSHL (data=b,
                   shift=a). Right shift uses the overflow-safe idiom
                   (val>>rs)+rbit; the naive (val + 2^(rs-1)) >> rs overflows
                   uint64 at esize=64. */
                case kS3RshlU: {
                    const int32_t shift = static_cast<int8_t>(a & 0xFFu);
                    if (shift >= 0) {
                        s = (shift >= 64) ? 0ull : (b << shift);
                    } else {
                        const uint32_t rs = static_cast<uint32_t>(-shift);
                        const uint64_t mainv = (rs >= 64u) ? 0ull : (b >> rs);
                        const uint64_t rbit  = (rs >= 65u) ? 0ull
                                                          : ((b >> (rs - 1u)) & 1ull);
                        s = mainv + rbit;
                    }
                    break;
                }
                case kS3RshlS: {
                    const int32_t shift = static_cast<int8_t>(a & 0xFFu);
                    const uint32_t sh = 64u - esize;
                    const int64_t val = static_cast<int64_t>(b << sh) >> sh;
                    if (shift >= 0) {
                        s = (shift >= 64) ? 0ull
                                          : (static_cast<uint64_t>(val) << shift);
                    } else {
                        const uint32_t rs = static_cast<uint32_t>(-shift);
                        const int64_t  mainv = (rs >= 64u) ? (val >> 63)
                                                          : (val >> rs);
                        const uint64_t rbit =
                            (rs >= 65u) ? (val < 0 ? 1ull : 0ull)
                                        : ((static_cast<uint64_t>(val) >> (rs - 1u)) & 1ull);
                        s = static_cast<uint64_t>(mainv + static_cast<int64_t>(rbit));
                    }
                    break;
                }
                default:
                    LOG(Caution, "HandleSimd3Same: unhandled op=%u\n", op);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            std::memcpy(res + e * ebytes, &s, ebytes);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeonSimd3Same::HandleSimd3SameHelper(ArmNeonSimd3Same* svc, uint32_t op,
                                                     uint32_t d_idx, uint32_t n_idx,
                                                     uint32_t m_idx, uint32_t esize,
                                                     uint32_t regs) {
    svc->HandleSimd3Same(op, d_idx, n_idx, m_idx, esize, regs);
}
