#include "bcd_calendar.h"

uint32_t BcdCalendar::ToBcd(uint32_t value) {
    return ((value / 10u) << 4) | (value % 10u);
}

uint32_t BcdCalendar::FromBcd(uint32_t value) {
    return ((value >> 4) & 0xFu) * 10u + (value & 0xFu);
}

/* S3C2410A UM p.17-1: "Leap year generator"; Epson RX-8564 ETM12E-03 section
   13.1.4 (p. 15): months 1, 3, 5, 7, 8, 10 and 12 have 31 days, 4, 6, 9 and 11
   have 30, and February has 29 when the year counter is a multiple of 4. */
uint32_t BcdCalendar::DaysInMonth(uint32_t month, uint32_t year) {
    static const uint32_t kLen[12] = {31u, 28u, 31u, 30u, 31u, 30u,
                                      31u, 31u, 30u, 31u, 30u, 31u};
    if (month == 2u && (year % 4u) == 0u) return 29u;
    return kLen[month - 1u];
}

std::tm BcdCalendar::HostLocalTime() {
    const std::time_t t = std::time(nullptr);
    std::tm           lt{};
    localtime_s(&lt, &t);
    return lt;
}
