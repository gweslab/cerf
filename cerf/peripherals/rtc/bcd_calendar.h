#pragma once

#include <cstdint>
#include <ctime>

class BcdCalendar {
public:
    static uint32_t ToBcd(uint32_t value);
    static uint32_t FromBcd(uint32_t value);

    static uint32_t DaysInMonth(uint32_t month, uint32_t year);
    static std::tm  HostLocalTime();
};
