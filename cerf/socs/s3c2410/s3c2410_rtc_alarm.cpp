#include "s3c2410_rtc_alarm.h"

namespace {

constexpr uint32_t kAlmEn   = 1u << 6;
constexpr uint32_t kAlmYear = 1u << 5;
constexpr uint32_t kAlmMon  = 1u << 4;
constexpr uint32_t kAlmDate = 1u << 3;
constexpr uint32_t kAlmHour = 1u << 2;
constexpr uint32_t kAlmMin  = 1u << 1;
constexpr uint32_t kAlmSec  = 1u << 0;

constexpr uint64_t kCalendarPeriodSecs = 36525ull * 86400ull;

using Cal = S3C2410RtcCalendar;

}

bool S3C2410RtcAlarm::Enabled() const { return (rtcalm & kAlmEn) != 0u; }

uint32_t S3C2410RtcAlarm::Mismatch(const Cal& c) const {
    if ((rtcalm & kAlmYear) != 0u && Cal::ToBcd(c.year) != (year & Cal::kYear.mask)) return kAlmYear;
    if ((rtcalm & kAlmMon)  != 0u && Cal::ToBcd(c.mon)  != (mon  & Cal::kMon.mask))  return kAlmMon;
    if ((rtcalm & kAlmDate) != 0u && Cal::ToBcd(c.date) != (date & Cal::kDate.mask)) return kAlmDate;
    if ((rtcalm & kAlmHour) != 0u && Cal::ToBcd(c.hour) != (hour & Cal::kHour.mask)) return kAlmHour;
    if ((rtcalm & kAlmMin)  != 0u && Cal::ToBcd(c.min)  != (min  & Cal::kMin.mask))  return kAlmMin;
    if ((rtcalm & kAlmSec)  != 0u && Cal::ToBcd(c.sec)  != (sec  & Cal::kSec.mask))  return kAlmSec;
    return 0u;
}

bool S3C2410RtcAlarm::Reachable() const {
    return ((rtcalm & kAlmYear) == 0u || Cal::IsCount(Cal::kYear, year)) &&
           ((rtcalm & kAlmMon)  == 0u || Cal::IsCount(Cal::kMon,  mon))  &&
           ((rtcalm & kAlmDate) == 0u || Cal::IsCount(Cal::kDate, date)) &&
           ((rtcalm & kAlmHour) == 0u || Cal::IsCount(Cal::kHour, hour)) &&
           ((rtcalm & kAlmMin)  == 0u || Cal::IsCount(Cal::kMin,  min))  &&
           ((rtcalm & kAlmSec)  == 0u || Cal::IsCount(Cal::kSec,  sec));
}

bool S3C2410RtcAlarm::Matches(const Cal& c) const { return Mismatch(c) == 0u; }

uint64_t S3C2410RtcAlarm::SecondsTo(Cal c) const {
    if (!Reachable()) return 0u;
    c.AdvanceSeconds(1u);
    for (uint64_t total = 1u; total <= kCalendarPeriodSecs;) {
        uint64_t step = 0;
        switch (Mismatch(c)) {
            case 0u:       return total;
            case kAlmYear: step = c.SecondsToNextYear();   break;
            case kAlmMon:  step = c.SecondsToNextMonth();  break;
            case kAlmDate: step = c.SecondsToNextDay();    break;
            case kAlmHour: step = c.SecondsToNextHour();   break;
            case kAlmMin:  step = c.SecondsToNextMinute(); break;
            default:       step = 1u;                      break;
        }
        c.AdvanceSeconds(step);
        total += step;
    }
    return 0u;
}

bool S3C2410RtcAlarm::Crossed(Cal from, uint64_t secs) const {
    if (!Enabled()) return false;
    for (uint64_t i = 0; i < secs; ++i) {
        from.AdvanceSeconds(1u);
        if (Matches(from)) return true;
    }
    return false;
}

void S3C2410RtcAlarm::Reset() {
    rtcalm = 0;
    sec    = 0;
    min    = 0;
    hour   = 0;
    date   = 0x01u;
    mon    = 0x01u;
    year   = 0;
}
