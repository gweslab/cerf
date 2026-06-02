#pragma once

#include <cstdint>

#include "../core/service.h"

/* VEXT — A8.8.316, byte-wise concat-and-select from (Dm:Dn) or
   (Qm:Qn). U=0, bit23=1, bits[21:20]=11, bit[4]=0. */
class ArmNeonVext : public Service {
public:
    using Service::Service;

    /* imm4_bytes: number of bytes from the LSB of the concatenated
       (m:n) vector to copy into dest. Range 0..7 for doubleword,
       0..15 for quadword. */
    void HandleVext(uint32_t d_idx, uint32_t n_idx, uint32_t m_idx,
                    uint32_t imm4_bytes, uint32_t q);

    static void __cdecl HandleVextHelper(ArmNeonVext* svc,
                                         uint32_t     d_idx,
                                         uint32_t     n_idx,
                                         uint32_t     m_idx,
                                         uint32_t     imm4_bytes,
                                         uint32_t     q);
};
