#pragma once

#include <array>
#include <cstdint>

namespace Rtc8564Regs {

/* Epson RTC-8564 MQ322-04 section 8.1 (p. 5): register table. */
inline constexpr uint8_t kControl1     = 0x00u;
inline constexpr uint8_t kControl2     = 0x01u;
inline constexpr uint8_t kSeconds      = 0x02u;
inline constexpr uint8_t kMinutes      = 0x03u;
inline constexpr uint8_t kHours        = 0x04u;
inline constexpr uint8_t kDays         = 0x05u;
inline constexpr uint8_t kWeekdays     = 0x06u;
inline constexpr uint8_t kMonths       = 0x07u;
inline constexpr uint8_t kYears        = 0x08u;
inline constexpr uint8_t kTimerControl = 0x0Eu;
inline constexpr uint8_t kTimer        = 0x0Fu;

/* MQ322-04 sections 8.2.1-8.2.2 (pp. 5-6) and 8.2.4 (p. 7). */
inline constexpr uint8_t kStop         = 0x20u;
inline constexpr uint8_t kTie          = 0x01u;
inline constexpr uint8_t kAie          = 0x02u;
inline constexpr uint8_t kTf           = 0x04u;
inline constexpr uint8_t kAf           = 0x08u;
inline constexpr uint8_t kTiTp         = 0x10u;
inline constexpr uint8_t kAlarmDisable = 0x80u;

using File = std::array<uint8_t, 16>;

}
