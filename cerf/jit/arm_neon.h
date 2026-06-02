#pragma once

#include <cstdint>

#include "../core/service.h"

/* NEON (Advanced SIMD) semantics. Operates on the shared VFP/NEON
   register file ArmCpuState::vfp_d[32] (D0..D31 aliased as Q0..Q15) —
   the same storage as ArmVfp, not a separate register array. */
class ArmNeon : public Service {
public:
    using Service::Service;

    /* VDUP (ARM core register), DDI0406C A8.8.314: broadcast
       Rt<esize-1:0> to every element of Dd (regs=1) or Dd:Dd+1
       (regs=2). Returns 1 (UND raised) on UNDEFINED/UNPREDICTABLE
       encodings, else 0; emit RETNs the block on non-zero. */
    uint32_t HandleVdup(uint32_t pc, uint32_t d_idx, uint32_t rt_idx,
                        uint32_t esize, uint32_t regs);

    static uint32_t __cdecl HandleVdupHelper(ArmNeon* neon, uint32_t pc,
                                             uint32_t d_idx, uint32_t rt_idx,
                                             uint32_t esize, uint32_t regs);

    static constexpr uint32_t kLsLoad = 1u << 0;  /* flags bit0: 1=VLD1, 0=VST1 */

    /* VLD1 / VST1 (multiple single elements),
       DDI0406C A8.8.320 / A8.8.404. */
    uint32_t HandleLoadStoreMultiple(uint32_t pc, uint32_t d_idx, uint32_t rn_idx,
                                     uint32_t rm_idx, uint32_t flags);

    static uint32_t __cdecl HandleLoadStoreMultipleHelper(ArmNeon* neon, uint32_t pc,
                                                          uint32_t d_idx, uint32_t rn_idx,
                                                          uint32_t rm_idx, uint32_t flags);

    /* VLD2/3/4 + VST2/3/4 (multiple N-element structures, de-interleaved),
       DDI0406C A8.8.323/326/329 / A8.8.406/408/410. */
    uint32_t HandleLoadStoreInterleaved(uint32_t pc, uint32_t d_idx, uint32_t rn_idx,
                                        uint32_t rm_idx, uint32_t flags);

    static uint32_t __cdecl HandleLoadStoreInterleavedHelper(ArmNeon* neon, uint32_t pc,
                                                             uint32_t d_idx, uint32_t rn_idx,
                                                             uint32_t rm_idx, uint32_t flags);

    /* VLD1/2/3/4 + VST1/2/3/4 (single element to one lane), DDI0406C
       A8.8.321/324/327/330 (load), A8.8.405/407/409/411 (store). flags:
       bit0=load, bits[2:1]=N-1, bit3=inc-1, bits[5:4]=size, bits[8:6]=index,
       bits[11:9]=align_log2. Returns 1 (UND/abort raised) on fault, else 0. */
    uint32_t HandleLoadStoreSingleLane(uint32_t pc, uint32_t d_idx, uint32_t rn_idx,
                                       uint32_t rm_idx, uint32_t flags);

    static uint32_t __cdecl HandleLoadStoreSingleLaneHelper(ArmNeon* neon, uint32_t pc,
                                                            uint32_t d_idx, uint32_t rn_idx,
                                                            uint32_t rm_idx, uint32_t flags);

    /* 3-reg-same accumulate ops (A7.4.1): d = f(d_old, n*m). Different
       handler from HandleSimd3Same because each element must pre-read
       the destination. size==11 UNDEFINED.
       A8.8.336 VMLA (kAccMla), A8.8.336 VMLS (kAccMls). */
    static constexpr uint32_t kAccMla  = 0u;  /* d = d + n*m              */
    static constexpr uint32_t kAccMls  = 1u;  /* d = d - n*m              */
    /* A8.8.277 VABA (S/U): d = d + |n-m| (signed/unsigned absdiff). */
    static constexpr uint32_t kAccAbaS = 2u;  /* d = d + |sext(n)-sext(m)| */
    static constexpr uint32_t kAccAbaU = 3u;  /* d = d + |n-m|             */
    void HandleSimd3SameAcc(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                            uint32_t m_idx, uint32_t esize, uint32_t regs);
    static void __cdecl HandleSimd3SameAccHelper(ArmNeon* neon, uint32_t op,
                                                 uint32_t d_idx, uint32_t n_idx,
                                                 uint32_t m_idx, uint32_t esize,
                                                 uint32_t regs);

    /* Pairwise reduction WITHIN each input register — low half of Dd from
       Dn pairs, high half from Dm pairs (NOT n[e]/m[e] like HandleSimd3Same).
       Doubleword only (Q=0). A8.8.362 VPADD, A8.8.365 VPMAX/VPMIN. */
    static constexpr uint32_t kPwAdd  = 0u;   /* VPADD                       */
    static constexpr uint32_t kPwMaxS = 1u;   /* VPMAX signed                */
    static constexpr uint32_t kPwMaxU = 2u;   /* VPMAX unsigned              */
    static constexpr uint32_t kPwMinS = 3u;   /* VPMIN signed                */
    static constexpr uint32_t kPwMinU = 4u;   /* VPMIN unsigned              */
    void HandleSimd3SamePairwise(uint32_t op, uint32_t d_idx, uint32_t n_idx,
                                 uint32_t m_idx, uint32_t esize);
    static void __cdecl HandleSimd3SamePairwiseHelper(ArmNeon* neon, uint32_t op,
                                                      uint32_t d_idx, uint32_t n_idx,
                                                      uint32_t m_idx, uint32_t esize);
};
