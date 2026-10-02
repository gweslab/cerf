#include "rtc8564_calendar.h"

#include "../../core/tick_scale.h"
#include "../../state/state_stream.h"

#include <algorithm>

namespace {

using namespace Rtc8564Regs;

uint8_t Bcd(uint32_t value) { return static_cast<uint8_t>(BcdCalendar::ToBcd(value)); }

struct AlarmField {
    uint8_t                          reg;
    BcdCalendar::Field               field;
    bool                             per_day;
    uint8_t Rtc8564Calendar::Time::* value;
};

constexpr AlarmField kAlarmFields[4] = {
    {kMinuteAlarm, Rtc8564Calendar::kMin, false, &Rtc8564Calendar::Time::min},
    {kHourAlarm, Rtc8564Calendar::kHour, false, &Rtc8564Calendar::Time::hour},
    {kDayAlarm, Rtc8564Calendar::kDay, true, &Rtc8564Calendar::Time::day},
    {kWeekdayAlarm, Rtc8564Calendar::kWday, true, &Rtc8564Calendar::Time::wday},
};

bool Accepts(const File& regs, const AlarmField& f, uint32_t value) {
    const uint8_t reg = regs[f.reg];
    if ((reg & kAlarmDisable) != 0u) return true;
    return (reg & f.field.mask) == BcdCalendar::ToBcd(value);
}

bool FieldCanMatch(const File& regs, const AlarmField& f) {
    const uint8_t reg = regs[f.reg];
    return (reg & kAlarmDisable) != 0u || BcdCalendar::IsCount(f.field, reg);
}

}

bool Rtc8564Calendar::Parse(const Rtc8564Regs::File& regs, Time& out) {
    uint32_t sec = 0, min = 0, hour = 0, day = 0, wday = 0, month = 0, year = 0;
    if (!DecodeField(kSec, regs[kSeconds], sec) || !DecodeField(kMin, regs[kMinutes], min) ||
        !DecodeField(kHour, regs[kHours], hour) || !DecodeField(kWday, regs[kWeekdays], wday) ||
        !DecodeField(kMonth, regs[kMonths], month) || !DecodeField(kYear, regs[kYears], year) ||
        !DecodeField(kDay, regs[kDays], day) || day > DaysInMonth(month, year)) {
        return false;
    }
    out.sec     = static_cast<uint8_t>(sec);
    out.min     = static_cast<uint8_t>(min);
    out.hour    = static_cast<uint8_t>(hour);
    out.day     = static_cast<uint8_t>(day);
    out.wday    = static_cast<uint8_t>(wday);
    out.month   = static_cast<uint8_t>(month);
    out.year    = static_cast<uint8_t>(year);
    out.century = (regs[kMonths] & kCentury) != 0u;
    return true;
}

bool Rtc8564Calendar::Load(uint64_t cpu_hz, uint64_t now, const Time& t, uint64_t phase,
                           uint64_t den) {
    if (!second_.SetRatio(cpu_hz, 1u) || !second_.AnchorAtPhase(now, 0u, phase, den)) return false;
    cpu_hz_     = cpu_hz;
    t_          = t;
    applied_    = 0;
    anchor_sec_ = t.sec;
    return true;
}

bool Rtc8564Calendar::SeedFromHost(uint64_t cpu_hz, uint64_t now, int year_base, int& host_year) {
    const HostDate host = HostNow();
    host_year           = static_cast<int>(host.year);
    const int year      = host_year - year_base;
    if (year < 0 || year > 99) return false;
    Time t;
    t.sec   = static_cast<uint8_t>(host.sec);
    t.min   = static_cast<uint8_t>(host.min);
    t.hour  = static_cast<uint8_t>(host.hour);
    t.day   = static_cast<uint8_t>(host.date);
    t.wday  = static_cast<uint8_t>(host.wday);
    t.month = static_cast<uint8_t>(host.month);
    t.year  = static_cast<uint8_t>(year);
    return Load(cpu_hz, now, t, 0u, 1u);
}

void Rtc8564Calendar::SaveState(StateWriter& w, uint64_t now, bool stopped) const {
    static_assert(StateVisitCoversAllBytes<Time>([](Time& t, StateFieldBytes& f) { Time::Visit(t, f); }),
                  "Rtc8564Calendar::Time::Visit must name every field of Time");
    Time            t = t_;
    StateWriteField field(w);
    Time::Visit(t, field);
    w.Write("cal_alarm_latched", alarm_latched_);
    w.Write<uint64_t>("cal_phase", stopped ? 0u : second_.PhaseAt(now));
    w.Write<uint64_t>("cal_phase_den", second_.PhaseDenominator());
}

void Rtc8564Calendar::RestoreState(StateReader& r, uint64_t cpu_hz, uint64_t now) {
    Time     t;
    bool     latched = false;
    uint64_t phase = 0, den = 1;
    StateReadField field(r);
    Time::Visit(t, field);
    r.Read("cal_alarm_latched", latched);
    r.Read("cal_phase", phase);
    r.Read("cal_phase_den", den);
    Load(cpu_hz, now, t, phase, den);
    alarm_latched_ = latched;
}

bool Rtc8564Calendar::Rescale(uint64_t now, uint64_t cpu_hz, Rtc8564Regs::File& regs) {
    Advance(now, regs);
    if (!second_.Rescale(now, cpu_hz, 1u)) return false;
    cpu_hz_     = cpu_hz;
    applied_    = 0;
    anchor_sec_ = t_.sec;
    return true;
}

/* ETM11J-07 section 13.1.4 (p. 15): years run 00-99 and the C bit sets when
   the year counter overflows from 99 to 00. Section 13.1.5: the weekday
   counter steps once per day through 0-6. */
void Rtc8564Calendar::StepDay(Time& t) {
    t.wday         = static_cast<uint8_t>((t.wday + 1u) % 7u);
    uint32_t date  = t.day;
    uint32_t month = t.month;
    uint32_t year  = t.year;
    if (NextDate(date, month, year)) t.century = true;
    t.day   = static_cast<uint8_t>(date);
    t.month = static_cast<uint8_t>(month);
    t.year  = static_cast<uint8_t>(year);
}

void Rtc8564Calendar::Advance(uint64_t now, Rtc8564Regs::File& regs) {
    const uint64_t k = second_.TicksSince(now);
    while (applied_ < k) {
        const uint64_t step = std::min<uint64_t>(k - applied_, 60u - t_.sec);
        applied_ += step;
        uint32_t sec  = t_.sec;
        uint32_t min  = t_.min;
        uint32_t hour = t_.hour;
        for (uint64_t days = AddSeconds(sec, min, hour, step); days > 0u; --days) StepDay(t_);
        t_.sec  = static_cast<uint8_t>(sec);
        t_.min  = static_cast<uint8_t>(min);
        t_.hour = static_cast<uint8_t>(hour);
        if (t_.sec == 0u) EvaluateAlarm(regs);
    }
}

bool Rtc8564Calendar::AnyAlarmFieldEnabled(const Rtc8564Regs::File& regs) {
    for (const AlarmField& f : kAlarmFields) {
        if ((regs[f.reg] & kAlarmDisable) == 0u) return true;
    }
    return false;
}

bool Rtc8564Calendar::FieldsMatch(const Rtc8564Regs::File& regs, const Time& t) {
    if (!AnyAlarmFieldEnabled(regs)) return false;
    for (const AlarmField& f : kAlarmFields) {
        if (!Accepts(regs, f, t.*f.value)) return false;
    }
    return true;
}

bool Rtc8564Calendar::DayCanMatch(const Rtc8564Regs::File& regs, const Time& t) {
    for (const AlarmField& f : kAlarmFields) {
        if (f.per_day && !Accepts(regs, f, t.*f.value)) return false;
    }
    return true;
}

/* Epson MQ322-04 section 8.2.4 (p. 7): the alarm occurs when the time comes to
   match every field with AE = 0, and not again until the match has ended. */
bool Rtc8564Calendar::NextAlarmCycle(const Rtc8564Regs::File& regs, uint64_t& cycle) const {
    if (!AnyAlarmFieldEnabled(regs)) return false;
    for (const AlarmField& f : kAlarmFields) {
        if (!FieldCanMatch(regs, f)) return false;
    }
    constexpr uint32_t kCalendarRepeatDays = 10227u;
    const uint32_t     now_min             = t_.hour * 60u + t_.min;
    Time               day                 = t_;
    for (uint32_t d = 0; d <= kCalendarRepeatDays; ++d, StepDay(day)) {
        if (!DayCanMatch(regs, day)) continue;
        bool before = false;
        for (uint32_t m = 0; m < 1440u; ++m) {
            day.hour         = static_cast<uint8_t>(m / 60u);
            day.min          = static_cast<uint8_t>(m % 60u);
            const bool match = FieldsMatch(regs, day);
            if (match && !before && (d > 0u || m > now_min)) {
                const uint64_t minutes = static_cast<uint64_t>(d) * 1440u + m - now_min;
                cycle = second_.CycleOfTick(applied_ + minutes * 60u - t_.sec);
                return true;
            }
            before = match;
        }
    }
    return false;
}

/* ETM11J-07 section 13.3.2 (p. 26): AF sets when the time matches every alarm
   field with AE = 0, and no alarm occurs with all four AE set. Epson MQ322-04
   section 8.2.4 (p. 7): a new alarm needs the match to end first. */
void Rtc8564Calendar::EvaluateAlarm(Rtc8564Regs::File& regs) {
    const bool match = FieldsMatch(regs, t_);
    if (match && !alarm_latched_) regs[kControl2] |= kAf;
    alarm_latched_ = match;
}

void Rtc8564Calendar::Materialize(Rtc8564Regs::File& regs) const {
    regs[kSeconds]  = Bcd(t_.sec);
    regs[kMinutes]  = Bcd(t_.min);
    regs[kHours]    = Bcd(t_.hour);
    regs[kDays]     = Bcd(t_.day);
    regs[kWeekdays] = t_.wday;
    regs[kMonths]   = static_cast<uint8_t>((t_.century ? kCentury : 0u) | Bcd(t_.month));
    regs[kYears]    = Bcd(t_.year);
}

/* ETM11J-07 section 13.2.2 (p. 20): TD selects 4096 Hz, 64 Hz, the seconds
   update or the minutes update as the countdown source. */
uint64_t Rtc8564Calendar::SourceHz(uint8_t td) {
    constexpr uint64_t kHz[3] = {4096u, 64u, 1u};
    return kHz[td];
}

/* ETM11J-07 section 13.2.2 (p. 20) notes 2-3 and section 13.2.3 (p. 22): the
   countdown follows the internal seconds and minutes updates, so the first
   period is short by up to one source period. */
uint64_t Rtc8564Calendar::SourceTicks(uint8_t td, uint64_t now) const {
    if (td == 3u) return (second_.TicksSince(now) + anchor_sec_) / 60u;
    return ScaleU64(now - second_.AnchorCycle(), SourceHz(td), cpu_hz_);
}

uint64_t Rtc8564Calendar::CycleOfSourceTick(uint8_t td, uint64_t tick) const {
    if (td == 3u) return second_.CycleOfTick(tick * 60u - anchor_sec_);
    return second_.AnchorCycle() + ScaleU64Ceil(tick, cpu_hz_, SourceHz(td));
}
