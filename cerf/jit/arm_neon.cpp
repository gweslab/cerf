#include "arm_neon.h"

#include <cstring>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "arm_cpu.h"
#include "arm_mmu.h"

REGISTER_SERVICE(ArmNeon);

uint32_t ArmNeon::HandleVdup(uint32_t pc, uint32_t d_idx, uint32_t rt_idx,
                             uint32_t esize, uint32_t regs) {
    auto& cpu = emu_.Get<ArmCpu>();
    auto* state = cpu.State();

    /* UNDEFINED/UNPREDICTABLE encodings (DDI0406C A8.8.314) -> guest UND. */
    if (esize == 0u || (regs == 2u && (d_idx & 1u)) ||
        (d_idx + regs) > 32u || rt_idx == 15u) {
        cpu.RaiseUndefinedException(pc);
        return 1;
    }

    const uint32_t rt = state->gprs[rt_idx];
    uint64_t bcast;
    switch (esize) {
        case 8:  bcast = (rt & 0xFFu)   * 0x0101010101010101ull; break;
        case 16: bcast = (rt & 0xFFFFu) * 0x0001000100010001ull; break;
        default: bcast = static_cast<uint64_t>(rt) |
                         (static_cast<uint64_t>(rt) << 32);       break;  /* 32 */
    }
    for (uint32_t r = 0; r < regs; ++r) {
        state->vfp_d[d_idx + r] = bcast;
    }
    return 0;
}

uint32_t __cdecl ArmNeon::HandleVdupHelper(ArmNeon* neon, uint32_t pc,
                                           uint32_t d_idx, uint32_t rt_idx,
                                           uint32_t esize, uint32_t regs) {
    return neon->HandleVdup(pc, d_idx, rt_idx, esize, regs);
}

uint32_t ArmNeon::HandleLoadStoreMultiple(uint32_t pc, uint32_t d_idx, uint32_t rn_idx,
                                          uint32_t rm_idx, uint32_t flags) {
    auto& cpu = emu_.Get<ArmCpu>();
    auto& mmu = emu_.Get<ArmMmu>();
    auto* state = cpu.State();

    const bool     is_load    = (flags & kLsLoad) != 0;
    const uint32_t regs       = (flags >> 1) & 0x7u;
    const uint32_t alignment  = 1u << ((flags >> 4) & 0x7u);

    /* UNPREDICTABLE (A8.8.320/404): Rn==PC or list overruns D31. */
    if (rn_idx == 15u || (d_idx + regs) > 32u) {
        cpu.RaiseUndefinedException(pc);
        return 1;
    }

    const uint32_t base = state->gprs[rn_idx];
    if (alignment > 1u && (base & (alignment - 1u)) != 0u) {
        mmu.RaiseAlignmentFault(base);
        cpu.RaiseAbortDataException(pc);
        return 1;
    }

    /* Each D-register is 8 contiguous bytes; on little-endian the
       per-element loop (any esize) collapses to a contiguous copy. */
    uint8_t* vfp_base = reinterpret_cast<uint8_t*>(state->vfp_d);
    uint32_t addr = base;
    for (uint32_t r = 0; r < regs; ++r) {
        uint8_t* host = is_load ? mmu.TranslateRead (state, addr)
                                : mmu.TranslateWrite(state, addr);
        if (!host) {
            cpu.RaiseAbortDataException(pc);
            return 1;
        }
        const uint32_t off = (d_idx + r) * 8u;
        if (is_load) std::memcpy(vfp_base + off, host, 8);
        else         std::memcpy(host, vfp_base + off, 8);
        addr += 8u;
    }

    /* Writeback (A7.7.1): Rm==15 none; Rm==13 [Rn]! (+= 8*regs);
       else [Rn],Rm (+= R[m]). */
    if (rm_idx != 15u) {
        state->gprs[rn_idx] =
            base + (rm_idx != 13u ? state->gprs[rm_idx] : 8u * regs);
    }
    return 0;
}

uint32_t __cdecl ArmNeon::HandleLoadStoreMultipleHelper(ArmNeon* neon, uint32_t pc,
                                                        uint32_t d_idx, uint32_t rn_idx,
                                                        uint32_t rm_idx, uint32_t flags) {
    return neon->HandleLoadStoreMultiple(pc, d_idx, rn_idx, rm_idx, flags);
}

uint32_t ArmNeon::HandleLoadStoreInterleaved(uint32_t pc, uint32_t d_idx, uint32_t rn_idx,
                                             uint32_t rm_idx, uint32_t flags) {
    auto& cpu = emu_.Get<ArmCpu>();
    auto& mmu = emu_.Get<ArmMmu>();
    auto* state = cpu.State();

    const bool     is_load   = (flags & kLsLoad) != 0;
    const uint32_t nstreams  = ((flags >> 1) & 0x3u) + 2u;   /* 2..4 */
    const uint32_t regs      = ((flags >> 3) & 0x1u) + 1u;   /* 1..2 */
    const uint32_t inc       = ((flags >> 4) & 0x1u) + 1u;   /* 1..2 */
    const uint32_t ebytes    = 1u << ((flags >> 5) & 0x3u);  /* 1/2/4 */
    const uint32_t alignment = 1u << ((flags >> 7) & 0x7u);
    const uint32_t elements  = 8u / ebytes;

    /* UNPREDICTABLE: Rn==PC or the highest register overruns D31. */
    if (rn_idx == 15u || (d_idx + (nstreams - 1u) * inc + regs) > 32u) {
        cpu.RaiseUndefinedException(pc);
        return 1;
    }

    const uint32_t base = state->gprs[rn_idx];
    if (alignment > 1u && (base & (alignment - 1u)) != 0u) {
        mmu.RaiseAlignmentFault(base);
        cpu.RaiseAbortDataException(pc);
        return 1;
    }

    /* De-interleave (load) / interleave (store): N streams at
       D[d + k*inc + r], element e at byte offset e*ebytes; memory is
       read/written in interleaved order. */
    uint8_t* vfp_base = reinterpret_cast<uint8_t*>(state->vfp_d);
    uint32_t addr = base;
    for (uint32_t r = 0; r < regs; ++r) {
        for (uint32_t e = 0; e < elements; ++e) {
            for (uint32_t k = 0; k < nstreams; ++k) {
                uint8_t* host = is_load ? mmu.TranslateRead (state, addr)
                                        : mmu.TranslateWrite(state, addr);
                if (!host) {
                    cpu.RaiseAbortDataException(pc);
                    return 1;
                }
                uint8_t* lane = vfp_base + (d_idx + k * inc + r) * 8u + e * ebytes;
                if (is_load) std::memcpy(lane, host, ebytes);
                else         std::memcpy(host, lane, ebytes);
                addr += ebytes;
            }
        }
    }

    if (rm_idx != 15u) {
        state->gprs[rn_idx] =
            base + (rm_idx != 13u ? state->gprs[rm_idx] : nstreams * 8u * regs);
    }
    return 0;
}

uint32_t __cdecl ArmNeon::HandleLoadStoreInterleavedHelper(ArmNeon* neon, uint32_t pc,
                                                           uint32_t d_idx, uint32_t rn_idx,
                                                           uint32_t rm_idx, uint32_t flags) {
    return neon->HandleLoadStoreInterleaved(pc, d_idx, rn_idx, rm_idx, flags);
}

uint32_t ArmNeon::HandleLoadStoreSingleLane(uint32_t pc, uint32_t d_idx, uint32_t rn_idx,
                                            uint32_t rm_idx, uint32_t flags) {
    auto& cpu = emu_.Get<ArmCpu>();
    auto& mmu = emu_.Get<ArmMmu>();
    auto* state = cpu.State();

    const bool     is_load   = (flags & kLsLoad) != 0;
    const uint32_t nstreams  = ((flags >> 1) & 0x3u) + 1u;   /* N = 1..4 */
    const uint32_t inc       = ((flags >> 3) & 0x1u) + 1u;   /* 1..2 */
    const uint32_t ebytes    = 1u << ((flags >> 4) & 0x3u);  /* 1/2/4 */
    const uint32_t index     = (flags >> 6) & 0x7u;          /* lane */
    const uint32_t alignment = 1u << ((flags >> 9) & 0x7u);

    /* UNPREDICTABLE: Rn==PC or the highest register overruns D31. */
    if (rn_idx == 15u || (d_idx + (nstreams - 1u) * inc) > 31u) {
        cpu.RaiseUndefinedException(pc);
        return 1;
    }

    const uint32_t base = state->gprs[rn_idx];
    if (alignment > 1u && (base & (alignment - 1u)) != 0u) {
        mmu.RaiseAlignmentFault(base);
        cpu.RaiseAbortDataException(pc);
        return 1;
    }

    /* One element per register, at lane `index` of D[d + k*inc]. */
    uint8_t* vfp_base = reinterpret_cast<uint8_t*>(state->vfp_d);
    uint32_t addr = base;
    for (uint32_t k = 0; k < nstreams; ++k) {
        uint8_t* host = is_load ? mmu.TranslateRead (state, addr)
                                : mmu.TranslateWrite(state, addr);
        if (!host) {
            cpu.RaiseAbortDataException(pc);
            return 1;
        }
        uint8_t* lane = vfp_base + (d_idx + k * inc) * 8u + index * ebytes;
        if (is_load) std::memcpy(lane, host, ebytes);
        else         std::memcpy(host, lane, ebytes);
        addr += ebytes;
    }

    if (rm_idx != 15u) {
        state->gprs[rn_idx] =
            base + (rm_idx != 13u ? state->gprs[rm_idx] : nstreams * ebytes);
    }
    return 0;
}

uint32_t __cdecl ArmNeon::HandleLoadStoreSingleLaneHelper(ArmNeon* neon, uint32_t pc,
                                                          uint32_t d_idx, uint32_t rn_idx,
                                                          uint32_t rm_idx, uint32_t flags) {
    return neon->HandleLoadStoreSingleLane(pc, d_idx, rn_idx, rm_idx, flags);
}

void ArmNeon::HandleSimd3SameAcc(uint32_t op, uint32_t d_idx, uint32_t n_idx,
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
            uint64_t a = 0, b = 0, d = 0;
            std::memcpy(&a, dn + e * ebytes, ebytes);
            std::memcpy(&b, dm + e * ebytes, ebytes);
            std::memcpy(&d, dd + e * ebytes, ebytes);
            uint64_t s = 0;
            /* VMLA/VMLS: integer pseudocode is signedness-independent
               (A8.8.336 line 44559), so uint64 wrap matches both. */
            switch (op) {
                case kAccMla: s = d + a * b; break;
                case kAccMls: s = d - a * b; break;
                case kAccAbaU: s = d + ((a >= b) ? (a - b) : (b - a)); break;
                case kAccAbaS: {
                    const uint32_t sh   = 64u - esize;
                    const int64_t  sa   = static_cast<int64_t>(a << sh) >> sh;
                    const int64_t  sb   = static_cast<int64_t>(b << sh) >> sh;
                    const int64_t  diff = sa - sb;
                    s = d + static_cast<uint64_t>(diff < 0 ? -diff : diff);
                    break;
                }
                default:
                    LOG(Caution, "HandleSimd3SameAcc: unhandled op=%u\n", op);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            std::memcpy(res + e * ebytes, &s, ebytes);
        }
        std::memcpy(&state->vfp_d[d_idx + r], res, 8);
    }
}

void __cdecl ArmNeon::HandleSimd3SameAccHelper(ArmNeon* neon, uint32_t op,
                                               uint32_t d_idx, uint32_t n_idx,
                                               uint32_t m_idx, uint32_t esize,
                                               uint32_t regs) {
    neon->HandleSimd3SameAcc(op, d_idx, n_idx, m_idx, esize, regs);
}

void ArmNeon::HandleSimd3SamePairwise(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                                      uint32_t m_idx, uint32_t esize) {
    auto* state = emu_.Get<ArmCpu>().State();
    const uint32_t ebytes   = esize / 8u;
    const uint32_t elements = 8u / ebytes;
    const uint32_t h        = elements / 2u;
    const uint32_t sh       = 64u - esize;

    const uint8_t* dn = reinterpret_cast<const uint8_t*>(&state->vfp_d[n_idx]);
    const uint8_t* dm = reinterpret_cast<const uint8_t*>(&state->vfp_d[m_idx]);
    uint8_t res[8];

    for (uint32_t e = 0; e < elements; ++e) {
        const uint8_t* src  = (e < h) ? dn : dm;
        const uint32_t pair = (e < h) ? e   : (e - h);
        uint64_t p1 = 0, p2 = 0;
        std::memcpy(&p1, src + (2u * pair)       * ebytes, ebytes);
        std::memcpy(&p2, src + (2u * pair + 1u)  * ebytes, ebytes);
        uint64_t s = 0;
        switch (op) {
            case kPwAdd:  s = p1 + p2;                      break;
            case kPwMaxU: s = (p1 >= p2) ? p1 : p2;         break;
            case kPwMinU: s = (p1 <= p2) ? p1 : p2;         break;
            case kPwMaxS: {
                const int64_t sp1 = static_cast<int64_t>(p1 << sh) >> sh;
                const int64_t sp2 = static_cast<int64_t>(p2 << sh) >> sh;
                s = (sp1 >= sp2) ? p1 : p2;
                break;
            }
            case kPwMinS: {
                const int64_t sp1 = static_cast<int64_t>(p1 << sh) >> sh;
                const int64_t sp2 = static_cast<int64_t>(p2 << sh) >> sh;
                s = (sp1 <= sp2) ? p1 : p2;
                break;
            }
            default:
                LOG(Caution, "HandleSimd3SamePairwise: unhandled op=%u\n", op);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        std::memcpy(res + e * ebytes, &s, ebytes);
    }
    std::memcpy(&state->vfp_d[d_idx], res, 8);
}

void __cdecl ArmNeon::HandleSimd3SamePairwiseHelper(ArmNeon* neon, uint32_t op,
                                                    uint32_t d_idx, uint32_t n_idx,
                                                    uint32_t m_idx, uint32_t esize) {
    neon->HandleSimd3SamePairwise(op, d_idx, n_idx, m_idx, esize);
}
