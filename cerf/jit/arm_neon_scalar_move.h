#pragma once

#include <cstdint>

#include "../core/service.h"

/* VMOV (ARM core register to scalar) / VMOV (scalar to ARM core
   register) — A8.8.341 / A8.8.342, esize=8 and esize=16 lane
   transfers. (esize=32 is handled by EmitVfpSingleMove.) */
class ArmNeonScalarMove : public Service {
public:
    using Service::Service;

    void HandleCoreToScalar(uint32_t d_idx, uint32_t lane_index,
                            uint32_t esize, uint32_t rt_index);

    void HandleScalarToCore(uint32_t n_idx, uint32_t lane_index,
                            uint32_t esize, uint32_t unsigned_ext,
                            uint32_t rt_index);

    static void __cdecl HandleCoreToScalarHelper(ArmNeonScalarMove* svc,
                                                 uint32_t           d_idx,
                                                 uint32_t           lane_index,
                                                 uint32_t           esize,
                                                 uint32_t           rt_index);

    static void __cdecl HandleScalarToCoreHelper(ArmNeonScalarMove* svc,
                                                 uint32_t           n_idx,
                                                 uint32_t           lane_index,
                                                 uint32_t           esize,
                                                 uint32_t           unsigned_ext,
                                                 uint32_t           rt_index);
};
