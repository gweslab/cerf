#include "arm_neon.h"

#include <cstring>

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "arm_cpu.h"
#include "arm_interrupt_channel.h"
#include "arm_mmu.h"
#include "arm_mmu_state.h"
#include "arm_routed_access.h"

REGISTER_SERVICE(ArmNeon);

/* DDI 0406C.c A8.8.322/326/329/332: VLD1/2/3/4 to all lanes. */
uint32_t __cdecl ArmNeon::LoadAllLanesHelper(ArmNeon* neon, uint32_t pc,
                                            uint32_t w) {
    auto& cpu = neon->emu_.Get<ArmCpu>();
    auto& mmu = neon->emu_.Get<ArmMmu>();
    auto* state = cpu.State();
    const uint32_t size = (w >> 6) & 3u;
    const uint32_t aligned = (w >> 4) & 1u;
    const uint32_t count = ((w >> 8) & 3u) + 1u;
    const uint32_t stride = ((w >> 5) & 1u) + 1u;
    const uint32_t regs = count == 1u ? stride : count;
    const uint32_t step = count == 1u ? 1u : stride;
    const uint32_t d = ((w >> 18) & 16u) | ((w >> 12) & 15u);
    const uint32_t rn = (w >> 16) & 15u;
    const uint32_t rm = w & 15u;
    if ((size == 3u && (count != 4u || !aligned)) ||
        (count == 1u && size == 0u && aligned) ||
        (count == 3u && aligned) || rn == 15u || d + (regs - 1u) * step > 31u) {
        cpu.RaiseUndefinedException(pc);
        return 1;
    }
    const uint32_t bytes = size == 3u ? 4u : 1u << size;
    const uint32_t length = count * bytes;
    const uint32_t alignment = !aligned ? 1u :
        (count == 4u && size == 2u) ? 8u : length;
    const uint32_t base = state->gprs[rn];
    if (neon->AlignmentFaults(mmu, base, alignment, bytes, true)) {
        cpu.RaiseAbortDataException(pc);
        return 1;
    }
    uint8_t data[16]{};
    for (uint32_t offset = 0; offset < length; offset += bytes) {
        uint32_t done = 0;
        if (!mmu.AccessPaged(state, base + offset, data + offset, bytes,
                             true, false, &done)) {
            if (mmu.io_pending() && offset == 0u && done == 0u &&
                neon->emu_.Get<ArmInterruptChannel>().BackOutForIrq(pc)) {
                mmu.ClearIoPending();
                return 1;
            }
            if (!mmu.io_pending() || !neon->emu_.Get<ArmRoutedAccess>().WideAccess(
                    state, pc, base + offset + done, bytes - done,
                    data + offset + done, true)) {
                cpu.RaiseAbortDataException(pc);
                return 1;
            }
        }
    }
    for (uint32_t r = 0; r < regs; ++r) {
        auto* dst = reinterpret_cast<uint8_t*>(&state->vfp_d[d + r * step]);
        for (uint32_t lane = 0; lane < 8u; lane += bytes)
            std::memcpy(dst + lane, data + (count == 1u ? 0u : r * bytes), bytes);
    }
    if (rm != 15u) state->gprs[rn] = base + (rm == 13u ? length : state->gprs[rm]);
    return 0;
}

bool ArmNeon::AlignmentFaults(ArmMmu& mmu, uint32_t base, uint32_t alignment,
                              uint32_t ebytes, bool is_load) {
    const uint32_t required =
        alignment > 1u
            ? alignment
            : (mmu.State()->effective_control_register.bits.a ? ebytes : 1u);
    if (required > 1u && (base & (required - 1u)) != 0u) {
        mmu.RaiseAlignmentFault(base, !is_load);
        return true;
    }
    return false;
}

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
    const uint32_t ebytes     = 1u << ((flags >> 7) & 0x3u);
    const uint32_t granule    = ebytes == 8u ? 4u : ebytes;

    /* UNPREDICTABLE (A8.8.320/404): Rn==PC or list overruns D31. */
    if (rn_idx == 15u || (d_idx + regs) > 32u) {
        cpu.RaiseUndefinedException(pc);
        return 1;
    }

    const uint32_t base = state->gprs[rn_idx];
    if (AlignmentFaults(mmu, base, alignment, ebytes, is_load)) {
        cpu.RaiseAbortDataException(pc);
        return 1;
    }

    uint8_t* vfp_base = reinterpret_cast<uint8_t*>(state->vfp_d);
    uint32_t addr = base;
    for (uint32_t r = 0; r < regs; ++r) {
        uint8_t* dst  = vfp_base + (d_idx + r) * 8u;
        uint32_t done = 0;
        if (!mmu.AccessPaged(state, addr, dst, 8u, is_load, false, &done)) {
            if (!mmu.io_pending()) {
                cpu.RaiseAbortDataException(pc);
                return 1;
            }
            if (r == 0u && done == 0u &&
                emu_.Get<ArmInterruptChannel>().BackOutForIrq(pc)) {
                mmu.ClearIoPending();
                return 1;
            }
            /* DDI 0406C.c A8.8.320 VLD1 Operation, p. A8-899: each element is a
               separate MemU[address,ebytes] when ebytes != 8, and when
               ebytes == 8 the element is MemU[address,4] and MemU[address+4,4]. */
            for (uint32_t g = done / granule; g < 8u / granule; ++g) {
                const uint32_t off = g * granule;
                if (!emu_.Get<ArmRoutedAccess>().WideAccess(
                        state, pc, addr + off, granule, dst + off, is_load)) {
                    cpu.RaiseAbortDataException(pc);
                    return 1;
                }
            }
        }
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
    if (AlignmentFaults(mmu, base, alignment, ebytes, is_load)) {
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
                uint8_t* lane = vfp_base + (d_idx + k * inc + r) * 8u + e * ebytes;
                uint32_t done = 0;
                if (!mmu.AccessPaged(state, addr, lane, ebytes, is_load,
                                     false, &done)) {
                    if (mmu.io_pending() && r == 0u && e == 0u && k == 0u &&
                        done == 0u &&
                        emu_.Get<ArmInterruptChannel>().BackOutForIrq(pc)) {
                        mmu.ClearIoPending();
                        return 1;
                    }
                    if (!mmu.io_pending() ||
                        !emu_.Get<ArmRoutedAccess>().WideAccess(
                            state, pc, addr + done, ebytes - done,
                            lane + done, is_load)) {
                        cpu.RaiseAbortDataException(pc);
                        return 1;
                    }
                }
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
    if (AlignmentFaults(mmu, base, alignment, ebytes, is_load)) {
        cpu.RaiseAbortDataException(pc);
        return 1;
    }

    /* One element per register, at lane `index` of D[d + k*inc]. */
    uint8_t* vfp_base = reinterpret_cast<uint8_t*>(state->vfp_d);
    uint32_t addr = base;
    for (uint32_t k = 0; k < nstreams; ++k) {
        uint8_t* lane = vfp_base + (d_idx + k * inc) * 8u + index * ebytes;
        uint32_t done = 0;
        if (!mmu.AccessPaged(state, addr, lane, ebytes, is_load, false, &done)) {
            if (mmu.io_pending() && k == 0u && done == 0u &&
                emu_.Get<ArmInterruptChannel>().BackOutForIrq(pc)) {
                mmu.ClearIoPending();
                return 1;
            }
            if (!mmu.io_pending() ||
                !emu_.Get<ArmRoutedAccess>().WideAccess(
                    state, pc, addr + done, ebytes - done, lane + done,
                    is_load)) {
                cpu.RaiseAbortDataException(pc);
                return 1;
            }
        }
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
