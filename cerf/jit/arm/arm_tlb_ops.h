#pragma once

#include <cstdint>

#include "arm_mmu_state.h"

void ArmTlbFlushAll(ArmTlbUnit* unit);

struct ArmTlbInvalidation {
    uint32_t base;
    uint32_t span_bytes;
};

/* ARM DDI 0406C.d B3.10.1; DDI 0406C.c B3.19.2. */
ArmTlbInvalidation ArmTlbInvalidateByVa(ArmTlbUnit* unit,
                                        uint32_t process_id, uint32_t va);

void FillFastTlb(ArmTlbUnit* unit, uint32_t folded_va, uint8_t* host,
                 uint32_t pa, uint8_t asid, bool global, bool writable,
                 uint32_t span_bytes);

void FillFastTlbIo(ArmTlbUnit* unit, uint32_t folded_va, uint32_t pa,
                   uint8_t asid, bool global, bool writable,
                   uint32_t span_bytes);
