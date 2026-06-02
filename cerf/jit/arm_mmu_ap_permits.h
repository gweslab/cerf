#pragma once

#include <cstdint>

#include "arm_mmu_state.h"

/* Access-permission predicates over an AP field, shared by the page
   walker and the diagnostic peek path (same resolution order). */

template <ArmMmuAccess kAccess>
inline bool ApPermits(uint32_t page_ap, bool is_user_mode) {
    if constexpr (kAccess == ArmMmuAccess::kRead ||
                  kAccess == ArmMmuAccess::kExecute) {
        return !(is_user_mode && page_ap == 1u);
    } else if constexpr (kAccess == ArmMmuAccess::kReadWrite ||
                         kAccess == ArmMmuAccess::kWrite) {
        if (is_user_mode) return page_ap == 3u;
        return page_ap != 0u;
    } else {
        return false;
    }
}

/* v6+ AP[2:0]: APX=ap[2], base=ap[1:0]. Covers the 5 AP values the
   WinCE7 NK kernel writes via PG_V6_PROT_* (vmarm.h:43-47) and
   ARMV6_MMU_PTL2_KR0 (ksarm.h:77). AP=000/100/111 unused-by-kernel —
   denying them keeps a stray walk fail-closed. */
template <ArmMmuAccess kAccess>
inline bool ApPermitsV6(uint32_t ap, bool is_user_mode) {
    if (ap == 0u || ap == 4u) return false;
    const bool apx = (ap & 4u) != 0u;
    const uint32_t base = ap & 3u;
    if constexpr (kAccess == ArmMmuAccess::kRead ||
                  kAccess == ArmMmuAccess::kExecute) {
        return is_user_mode ? base >= 2u : true;
    } else if constexpr (kAccess == ArmMmuAccess::kReadWrite ||
                         kAccess == ArmMmuAccess::kWrite) {
        if (apx) return false;
        return is_user_mode ? base == 3u : true;
    } else {
        return false;
    }
}
