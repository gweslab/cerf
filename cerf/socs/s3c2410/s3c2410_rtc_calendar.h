#pragma once

#include "../../peripherals/rtc/bcd_calendar.h"

#include <cstdint>

class S3C2410RtcCalendar : public BcdCalendar {
public:
    static constexpr Field kSec {0x7Fu, 0u, 59u};
    static constexpr Field kMin {0x7Fu, 0u, 59u};
    static constexpr Field kHour{0x3Fu, 0u, 23u};
    static constexpr Field kDate{0x3Fu, 1u, 31u};
    static constexpr Field kMon {0x1Fu, 1u, 12u};
    static constexpr Field kYear{0xFFu, 0u, 99u};
    static constexpr Field kDay {0x07u, 1u, 7u};

    bool Valid() const;

    uint32_t sec  = 0;
    uint32_t min  = 0;
    uint32_t hour = 0;
    uint32_t date = 1;
    uint32_t day  = 1;
    uint32_t mon  = 1;
    uint32_t year = 0;

    void SeedFromHost();
    void AdvanceSeconds(uint64_t secs);

    uint64_t SecondsToNextMinute() const;
    uint64_t SecondsToNextHour() const;
    uint64_t SecondsToNextDay() const;
    uint64_t SecondsToNextMonth() const;
    uint64_t SecondsToNextYear() const;

private:
    void AdvanceOneDay();
};
