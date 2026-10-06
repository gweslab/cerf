#pragma once

#include "../rtc/bcd_calendar.h"

#include <array>
#include <cstdint>

class StateReader;
class StateWriter;

class Ds1386Clock : public BcdCalendar {
public:
    struct Time {
        uint8_t cs    = 0;
        uint8_t sec   = 0;
        uint8_t min   = 0;
        uint8_t hour  = 0;
        uint8_t wday  = 1;
        uint8_t date  = 1;
        uint8_t month = 1;
        uint8_t year  = 0;

        template <typename F>
        static constexpr void Visit(Time& t, F& field) {
            field("ds_cs", t.cs);
            field("ds_sec", t.sec);
            field("ds_min", t.min);
            field("ds_hour", t.hour);
            field("ds_wday", t.wday);
            field("ds_date", t.date);
            field("ds_month", t.month);
            field("ds_year", t.year);
        }
    };

    enum : uint8_t {
        kRegHundredths = 0x0, kRegSeconds = 0x1, kRegMinutes = 0x2, kRegMinuteAlarm = 0x3,
        kRegHours = 0x4, kRegHourAlarm = 0x5, kRegDays = 0x6, kRegDayAlarm = 0x7,
        kRegDate = 0x8, kRegMonths = 0x9, kRegYears = 0xA, kRegCount = 0xB,
    };

    using Regs = std::array<uint8_t, kRegCount>;

    /* DS1386 datasheet Figure 2 (p. 8): register fields and ranges. */
    static constexpr Field kCs    {0xFFu, 0u, 99u};
    static constexpr Field kSec   {0x7Fu, 0u, 59u};
    static constexpr Field kMin   {0x7Fu, 0u, 59u};
    static constexpr Field kHour24{0x3Fu, 0u, 23u};
    static constexpr Field kHour12{0x1Fu, 1u, 12u};
    static constexpr Field kWday  {0x07u, 1u, 7u};
    static constexpr Field kDate  {0x3Fu, 1u, 31u};
    static constexpr Field kMonth {0x1Fu, 1u, 12u};
    static constexpr Field kYear  {0xFFu, 0u, 99u};

    static constexpr uint8_t kHours12   = 0x40u;
    static constexpr uint8_t kHoursPm   = 0x20u;
    static constexpr uint8_t kAlarmMask = 0x80u;

    static constexpr uint64_t kNever = ~0ull;

    static uint64_t HundredthOf(uint64_t osc_ticks);
    static uint64_t OscTickOf(uint64_t hundredth);

    struct Advanced {
        uint32_t alarms;
        uint64_t last_alarm;
    };

    void Load(uint64_t hundredth, const Time& t);
    void SeedFromHost(uint64_t hundredth);

    Advanced Advance(uint64_t hundredth);
    uint64_t NextAlarmCheck();

    Regs Format() const;

    void SetField(uint8_t Time::* field, uint8_t value);
    void SetHours(uint8_t hour24, bool hours12);
    void SetAlarm(uint32_t which, uint8_t value);

    void Save(StateWriter& w) const;
    void Restore(StateReader& r);

private:
    static uint64_t CarryClock(Time& t, uint64_t seconds);
    static void     StepDays(Time& t, uint64_t days);
    static void     StepDay(Time& t);
    static void     StepMinute(Time& t);

    bool    LogicalMasks() const;
    bool    MinuteMatches(const Time& t) const;
    uint8_t HoursReg(uint8_t hour) const;
    void    Step(uint64_t hundredths);

    Time                   t_;
    uint64_t               at_          = 0;
    bool                   hours12_     = false;
    std::array<uint8_t, 3> alarm_       = {};
    bool                   check_known_ = false;
    uint64_t               check_at_    = kNever;
};
