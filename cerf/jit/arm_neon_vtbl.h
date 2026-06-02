#pragma once

#include <cstdint>

#include "../core/service.h"

/* VTBL / VTBX — A8.8.419, byte-wise table lookup of D[m]'s 8 indices
   into a 1-4 D-register table starting at D[n]. VTBL zero-fills bytes
   whose index is out of range; VTBX preserves D[d]'s original byte at
   those positions. */
class ArmNeonVtbl : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kTbl = 0u;
    static constexpr uint32_t kTbx = 1u;

    void HandleVtbl(uint32_t op_sel, uint32_t d_idx, uint32_t n_idx,
                    uint32_t m_idx, uint32_t length);

    static void __cdecl HandleVtblHelper(ArmNeonVtbl* svc,
                                         uint32_t     op_sel,
                                         uint32_t     d_idx,
                                         uint32_t     n_idx,
                                         uint32_t     m_idx,
                                         uint32_t     length);
};
