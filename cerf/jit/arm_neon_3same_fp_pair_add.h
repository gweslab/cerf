#pragma once

#include <cstdint>

#include "../core/service.h"

/* VPADD (floating-point) — A8.8.363, opc=1101 C=0 U=1 bit[21]=0. */
class ArmNeon3SameFpPairAdd : public Service {
public:
    using Service::Service;

    void Handle3SameFpPairAdd(uint32_t d_idx, uint32_t n_idx, uint32_t m_idx);

    static void __cdecl Handle3SameFpPairAddHelper(ArmNeon3SameFpPairAdd* svc,
                                                   uint32_t d_idx,
                                                   uint32_t n_idx,
                                                   uint32_t m_idx);
};
