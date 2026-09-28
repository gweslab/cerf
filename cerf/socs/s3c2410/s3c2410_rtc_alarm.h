#pragma once

#include "s3c2410_rtc_calendar.h"

#include <cstdint>

class S3C2410RtcAlarm {
public:
    uint32_t rtcalm = 0;
    uint32_t sec    = 0;
    uint32_t min    = 0;
    uint32_t hour   = 0;
    uint32_t date   = 0x01u;
    uint32_t mon    = 0x01u;
    uint32_t year   = 0;

    bool     Enabled() const;
    bool     Matches(const S3C2410RtcCalendar& c) const;
    uint64_t SecondsTo(S3C2410RtcCalendar c) const;
    bool     Crossed(S3C2410RtcCalendar from, uint64_t secs) const;
    void     Reset();

private:
    uint32_t Mismatch(const S3C2410RtcCalendar& c) const;
    bool     Reachable() const;
};
