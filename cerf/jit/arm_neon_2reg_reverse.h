#pragma once

#include <cstdint>

#include "../core/service.h"

/* VREV16/VREV32/VREV64 (A8.8.386). Per-element shuffle: dst[i] = src[i XOR
   (groupsize-1)] within each groupsize-wide window of elements. */
class ArmNeon2RegReverse : public Service {
public:
    using Service::Service;

    /* op is unused at runtime — kept for ArmPlaceFn signature parity, since
       the place_fn unifies arg-push order with siblings. */
    void HandleRev(uint32_t op, uint32_t d_idx, uint32_t m_idx,
                   uint32_t esize, uint32_t groupsize, uint32_t regs);

    static void __cdecl HandleRevHelper(ArmNeon2RegReverse* svc, uint32_t op,
                                        uint32_t d_idx, uint32_t m_idx,
                                        uint32_t esize, uint32_t groupsize,
                                        uint32_t regs);
};
