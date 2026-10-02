#pragma once

#include <cstdint>

class BcdCalendar {
public:
    struct HostDate {
        uint32_t sec   = 0;
        uint32_t min   = 0;
        uint32_t hour  = 0;
        uint32_t date  = 1;
        uint32_t month = 1;
        uint32_t year  = 0;
        uint32_t wday  = 0;
    };

    static uint32_t ToBcd(uint32_t value);
    static uint32_t FromBcd(uint32_t value);
    static bool     DecodeBcd(uint32_t bcd, uint32_t lo, uint32_t hi, uint32_t& out);

    static uint32_t DaysInMonth(uint32_t month, uint32_t year);
    static uint64_t AddSeconds(uint32_t& sec, uint32_t& min, uint32_t& hour, uint64_t secs);
    static bool     NextDate(uint32_t& date, uint32_t& month, uint32_t& year);
    static HostDate HostNow();
};
