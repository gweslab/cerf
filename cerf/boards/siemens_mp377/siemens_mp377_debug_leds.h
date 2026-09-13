#pragma once

#include <cstdint>

namespace siemens_mp377 {

/* siemens_mp377_v1040 nk.exe sub_804414A8 and sub_80441638. */
inline constexpr uint32_t kDebugLedProgressBase = 0xF2FFFFF6u;
inline constexpr uint32_t kDebugLedProgressEnd = 0xF2FFFFFEu;
inline constexpr uint32_t kDebugLedTickBase = 0xF3400020u;
inline constexpr uint32_t kDebugLedTickEnd = 0xF3400022u;

} // namespace siemens_mp377
