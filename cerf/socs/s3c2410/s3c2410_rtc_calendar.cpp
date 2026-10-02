#include "s3c2410_rtc_calendar.h"

bool S3C2410RtcCalendar::Holds(const Field& f, uint32_t value) {
    return value >= f.lo && value <= f.hi;
}

bool S3C2410RtcCalendar::IsCount(const Field& f, uint32_t bcd) {
    uint32_t value = 0;
    return DecodeBcd(bcd & f.mask, f.lo, f.hi, value);
}

bool S3C2410RtcCalendar::Valid() const {
    return Holds(kSec, sec) && Holds(kMin, min) && Holds(kHour, hour) &&
           Holds(kMon, mon) && Holds(kYear, year) && Holds(kDay, day) &&
           Holds(kDate, date) && date <= DaysInMonth(mon, year);
}

void S3C2410RtcCalendar::SeedFromHost() {
    const HostDate host = HostNow();
    sec  = host.sec;
    min  = host.min;
    hour = host.hour;
    date = host.date;
    mon  = host.month;
    year = host.year % 100u;
    day  = host.wday + 1u;
}

void S3C2410RtcCalendar::AdvanceOneDay() {
    day = day % 7u + 1u;
    NextDate(date, mon, year);
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
    for (uint64_t days = AddSeconds(sec, min, hour, secs); days > 0u; --days) AdvanceOneDay();
}
