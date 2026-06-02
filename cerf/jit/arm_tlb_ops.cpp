#include "arm_tlb_ops.h"

#include <cstring>

void ArmTlbFlushAll(ArmTlbUnit* unit) {
    /* tag == kArmTlbInvalidTag has low bits set, so it can never equal a
       page-aligned folded-VA tag — 0xFF-filling marks every entry empty. */
    std::memset(unit, 0xFF, sizeof(*unit));
}

void ArmTlbInvalidateByVa(ArmTlbUnit* unit, uint32_t process_id, uint32_t va) {
    /* FCSE fold for the low 32 MB slot; cp15 c8 runs regardless of SCTLR.M. */
    if ((va & 0xFE000000u) == 0u) {
        va |= process_id;
    }
    const uint32_t page = va & 0xFFFFF000u;
    const uint32_t base = ArmTlbSetBase(va);
    /* The page may sit in any way of its set — invalidate every match. */
    for (uint32_t w = 0; w < kArmTlbWays; ++w) {
        if (unit->entries[base + w].tag == page) {
            unit->entries[base + w].tag = kArmTlbInvalidTag;
        }
    }
}
