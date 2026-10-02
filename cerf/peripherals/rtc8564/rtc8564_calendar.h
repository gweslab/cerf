#pragma once

#include "../../socs/cycle_anchored_counter.h"
#include "../rtc/bcd_calendar.h"
#include "rtc8564_registers.h"

#include <cstdint>

class StateReader;
class StateWriter;

class Rtc8564Calendar : public BcdCalendar {
public:
    struct Time {
        uint8_t sec     = 0;
        uint8_t min     = 0;
        uint8_t hour    = 0;
        uint8_t day     = 1;
        uint8_t wday    = 0;
        uint8_t month   = 1;
        uint8_t year    = 0;
        bool    century = false;

        template <typename F>
        static constexpr void Visit(Time& t, F& field) {
            field("cal_sec", t.sec);
            field("cal_min", t.min);
            field("cal_hour", t.hour);
            field("cal_day", t.day);
            field("cal_wday", t.wday);
            field("cal_month", t.month);
            field("cal_year", t.year);
            field("cal_century", t.century);
        }
    };

    static constexpr Field kSec  {0x7Fu, 0u, 59u};
    static constexpr Field kMin  {0x7Fu, 0u, 59u};
    static constexpr Field kHour {0x3Fu, 0u, 23u};
    static constexpr Field kDay  {0x3Fu, 1u, 31u};
    static constexpr Field kWday {0x07u, 0u, 6u};
    static constexpr Field kMonth{0x1Fu, 1u, 12u};
    static constexpr Field kYear {0xFFu, 0u, 99u};

    static bool Parse(const Rtc8564Regs::File& regs, Time& out);

    bool Load(uint64_t cpu_hz, uint64_t now, const Time& t, uint64_t phase, uint64_t den);
    bool SeedFromHost(uint64_t cpu_hz, uint64_t now, int year_base, int& host_year);
    bool Rescale(uint64_t now, uint64_t cpu_hz, Rtc8564Regs::File& regs);
    void SaveState(StateWriter& w, uint64_t now, bool stopped) const;
    void RestoreState(StateReader& r, uint64_t cpu_hz, uint64_t now);

    void Advance(uint64_t now, Rtc8564Regs::File& regs);
    void EvaluateAlarm(Rtc8564Regs::File& regs);
    void Materialize(Rtc8564Regs::File& regs) const;

    bool     NextAlarmCycle(const Rtc8564Regs::File& regs, uint64_t& cycle) const;
    uint64_t SourceTicks(uint8_t td, uint64_t now) const;
    uint64_t CycleOfSourceTick(uint8_t td, uint64_t tick) const;

private:
    static uint64_t SourceHz(uint8_t td);
    static bool     AnyAlarmFieldEnabled(const Rtc8564Regs::File& regs);
    static bool     FieldsMatch(const Rtc8564Regs::File& regs, const Time& t);
    static bool     DayCanMatch(const Rtc8564Regs::File& regs, const Time& t);
    static void     StepDay(Time& t);

    CycleAnchoredCounter second_;
    Time                 t_;
    uint64_t             applied_       = 0;
    uint8_t              anchor_sec_    = 0;
    uint64_t             cpu_hz_        = 1;
    bool                 alarm_latched_ = false;
};
