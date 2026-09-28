#include "s3c2410_rtc_calendar.h"

bool S3C2410RtcCalendar::Holds(const Field& f, uint32_t value) {
    return value >= f.lo && value <= f.hi;
}

bool S3C2410RtcCalendar::IsCount(const Field& f, uint32_t bcd) {
    const uint32_t v = bcd & f.mask;
    return (v & 0xFu) <= 9u && (v >> 4) <= 9u && Holds(f, FromBcd(v));
}

bool S3C2410RtcCalendar::Valid() const {
    return Holds(kSec, sec) && Holds(kMin, min) && Holds(kHour, hour) &&
           Holds(kMon, mon) && Holds(kYear, year) && Holds(kDay, day) &&
           Holds(kDate, date) && date <= DaysInMonth(mon, year);
}

void S3C2410RtcCalendar::SeedFromHost() {
    const std::tm lt = HostLocalTime();
    sec  = static_cast<uint32_t>(lt.tm_sec % 60);
    min  = static_cast<uint32_t>(lt.tm_min);
    hour = static_cast<uint32_t>(lt.tm_hour);
    date = static_cast<uint32_t>(lt.tm_mday);
    mon  = static_cast<uint32_t>(lt.tm_mon + 1);
    year = static_cast<uint32_t>((lt.tm_year + 1900) % 100);
    day  = static_cast<uint32_t>(lt.tm_wday + 1);
}

void S3C2410RtcCalendar::AdvanceOneDay() {
    day = day % 7u + 1u;
    if (date < DaysInMonth(mon, year)) {
        ++date;
        return;
    }
    date = 1u;
    if (mon < 12u) {
        ++mon;
        return;
    }
    mon  = 1u;
    year = (year + 1u) % 100u;
}

uint64_t S3C2410RtcCalendar::SecondsToNextMinute() const {
    return 60u - sec;
}

uint64_t S3C2410RtcCalendar::SecondsToNextHour() const {
    return 3600u - (min * 60u + sec);
}

uint64_t S3C2410RtcCalendar::SecondsToNextDay() const {
    return 86400u - (hour * 3600u + min * 60u + sec);
}

uint64_t S3C2410RtcCalendar::SecondsToNextMonth() const {
    return SecondsToNextDay() + static_cast<uint64_t>(DaysInMonth(mon, year) - date) * 86400u;
}

uint64_t S3C2410RtcCalendar::SecondsToNextYear() const {
    uint64_t days = 0;
    for (uint32_t m = mon + 1u; m <= 12u; ++m) days += DaysInMonth(m, year);
    return SecondsToNextMonth() + days * 86400u;
}

void S3C2410RtcCalendar::AdvanceSeconds(uint64_t secs) {
    uint64_t t = sec + secs;
    sec  = static_cast<uint32_t>(t % 60u);
    t    = min + t / 60u;
    min  = static_cast<uint32_t>(t % 60u);
    t    = hour + t / 60u;
    hour = static_cast<uint32_t>(t % 24u);
    for (uint64_t days = t / 24u; days > 0u; --days) AdvanceOneDay();
}
