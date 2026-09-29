#pragma once

#include <cstdint>

inline bool CycleDeadlineReached(uint32_t counter, uint32_t deadline) {
    return static_cast<int32_t>(counter - deadline) >= 0;
}
