#pragma once

#include <cstdint>

namespace siemens_mp377 {

inline constexpr uint32_t kMp377PowerResetBase = 0xD0180000u;
inline constexpr uint32_t kMp377PowerResetBlockBytes = 0x1000u;
inline constexpr uint32_t kMp377PowerResetBlockCount = 3u;
inline constexpr uint32_t kMp377PowerResetEnd =
    kMp377PowerResetBase + kMp377PowerResetBlockBytes * kMp377PowerResetBlockCount;

/* siemens_mp377_v1040 nk.exe sub_80445460 (BSPIntrInit). */
inline constexpr uint32_t kMp377PowerFailIrqSource = 0x1Fu;

} // namespace siemens_mp377
