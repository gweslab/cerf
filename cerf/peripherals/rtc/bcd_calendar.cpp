#include "bcd_calendar.h"

#include <algorithm>
#include <ctime>

uint32_t BcdCalendar::ToBcd(uint32_t value) {
    return ((value / 10u) << 4) | (value % 10u);
}

uint32_t BcdCalendar::FromBcd(uint32_t value) {
    return ((value >> 4) & 0xFu) * 10u + (value & 0xFu);
}

bool BcdCalendar::DecodeBcd(uint32_t bcd, uint32_t lo, uint32_t hi, uint32_t& out) {
    if ((bcd & 0xFu) > 9u || (bcd >> 4) > 9u) return false;
    out = FromBcd(bcd);
    return out >= lo && out <= hi;
}

bool BcdCalendar::DecodeField(const Field& f, uint32_t bcd, uint32_t& out) {
    return DecodeBcd(bcd & f.mask, f.lo, f.hi, out);
}

bool BcdCalendar::IsCount(const Field& f, uint32_t bcd) {
    uint32_t value = 0;
    return DecodeField(f, bcd, value);
}

bool BcdCalendar::Holds(const Field& f, uint32_t value) {
    return value >= f.lo && value <= f.hi;
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

uint64_t BcdCalendar::AddSeconds(uint32_t& sec, uint32_t& min, uint32_t& hour, uint64_t secs) {
    uint64_t t = sec + secs;
    sec        = static_cast<uint32_t>(t % 60u);
    t          = min + t / 60u;
    min        = static_cast<uint32_t>(t % 60u);
    t          = hour + t / 60u;
    hour       = static_cast<uint32_t>(t % 24u);
    return t / 24u;
}

bool BcdCalendar::NextDate(uint32_t& date, uint32_t& month, uint32_t& year) {
    if (++date <= DaysInMonth(month, year)) return false;
    date = 1u;
    if (++month <= 12u) return false;
    month = 1u;
    if (++year <= 99u) return false;
    year = 0u;
    return true;
}

BcdCalendar::HostDate BcdCalendar::HostNow() {
    const std::time_t t = std::time(nullptr);
    std::tm           lt{};
    localtime_s(&lt, &t);
    HostDate d;
    d.sec   = static_cast<uint32_t>(std::min(lt.tm_sec, 59));
    d.min   = static_cast<uint32_t>(lt.tm_min);
    d.hour  = static_cast<uint32_t>(lt.tm_hour);
    d.date  = static_cast<uint32_t>(lt.tm_mday);
    d.month = static_cast<uint32_t>(lt.tm_mon + 1);
    d.year  = static_cast<uint32_t>(lt.tm_year + 1900);
    d.wday  = static_cast<uint32_t>(lt.tm_wday);
    return d;
}
