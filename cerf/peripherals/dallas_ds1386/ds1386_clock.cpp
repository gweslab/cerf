#include "ds1386_clock.h"

#include "../../state/state_stream.h"

namespace {

constexpr uint64_t kHundredthsPerMinute = 6000u;
constexpr uint32_t kMinutesPerWeek      = 7u * 24u * 60u;

uint8_t Bcd(uint32_t value) { return static_cast<uint8_t>(BcdCalendar::ToBcd(value)); }

}

/* DS1386 datasheet Figure 1 (p. 5): 32.768 kHz divided by 8, then by 40.96, is
   the 100 Hz "AVG" that clocks the hundredths. */
uint64_t Ds1386Clock::HundredthOf(uint64_t osc_ticks) { return osc_ticks * 25u / 8192u; }

uint64_t Ds1386Clock::OscTickOf(uint64_t hundredth) { return (hundredth * 8192u + 24u) / 25u; }

void Ds1386Clock::Load(uint64_t hundredth, const Time& t) {
    at_          = hundredth;
    t_           = t;
    check_known_ = false;
}

void Ds1386Clock::SeedFromHost(uint64_t hundredth) {
    const HostDate host = HostNow();
    Time           t;
    t.sec   = static_cast<uint8_t>(host.sec);
    t.min   = static_cast<uint8_t>(host.min);
    t.hour  = static_cast<uint8_t>(host.hour);
    t.wday  = static_cast<uint8_t>(host.wday + 1u);
    t.date  = static_cast<uint8_t>(host.date);
    t.month = static_cast<uint8_t>(host.month);
    t.year  = static_cast<uint8_t>(host.year % 100u);
    Load(hundredth, t);
}

/* DS1386 datasheet Figure 2 (p. 8): DAYS counts 01-07. */
void Ds1386Clock::StepDay(Time& t) {
    t.wday         = static_cast<uint8_t>(t.wday % 7u + 1u);
    uint32_t date  = t.date;
    uint32_t month = t.month;
    uint32_t year  = t.year;
    NextDate(date, month, year);
    t.date  = static_cast<uint8_t>(date);
    t.month = static_cast<uint8_t>(month);
    t.year  = static_cast<uint8_t>(year);
}

uint64_t Ds1386Clock::CarryClock(Time& t, uint64_t seconds) {
    uint32_t       sec  = t.sec;
    uint32_t       min  = t.min;
    uint32_t       hour = t.hour;
    const uint64_t days = AddSeconds(sec, min, hour, seconds);
    t.sec               = static_cast<uint8_t>(sec);
    t.min               = static_cast<uint8_t>(min);
    t.hour              = static_cast<uint8_t>(hour);
    return days;
}

void Ds1386Clock::StepDays(Time& t, uint64_t days) {
    for (; days > 0u; --days) StepDay(t);
}

void Ds1386Clock::StepMinute(Time& t) { StepDays(t, CarryClock(t, 60u)); }

void Ds1386Clock::Step(uint64_t hundredths) {
    const uint64_t total = t_.cs + hundredths;
    t_.cs                = static_cast<uint8_t>(total % 100u);
    StepDays(t_, CarryClock(t_, total / 100u));
    at_ += hundredths;
}

/* DS1386 datasheet Table 1 (p. 8): the four mask combinations it defines; "Any
   other bit combinations of mask bit settings produce illogical operation." */
bool Ds1386Clock::LogicalMasks() const {
    const bool m3 = (alarm_[0] & kAlarmMask) != 0u;
    const bool m5 = (alarm_[1] & kAlarmMask) != 0u;
    const bool m7 = (alarm_[2] & kAlarmMask) != 0u;
    return (!m3 || m5) && (!m5 || m7);
}

uint8_t Ds1386Clock::HoursReg(uint8_t hour) const {
    if (!hours12_) return Bcd(hour);
    const uint32_t h12 = hour % 12u == 0u ? 12u : hour % 12u;
    return static_cast<uint8_t>(Bcd(h12) | kHours12 | (hour >= 12u ? kHoursPm : 0u));
}

/* DS1386 datasheet p. 6: with every mask bit 0 the alarm occurs when registers
   2, 4 and 6 match the values in registers 3, 5 and 7. */
bool Ds1386Clock::MinuteMatches(const Time& t) const {
    if ((alarm_[0] & kAlarmMask) == 0u && Bcd(t.min) != (alarm_[0] & 0x7Fu)) return false;
    if ((alarm_[1] & kAlarmMask) == 0u && HoursReg(t.hour) != (alarm_[1] & 0x7Fu)) return false;
    if ((alarm_[2] & kAlarmMask) == 0u && t.wday != (alarm_[2] & 0x07u)) return false;
    return true;
}

/* DS1386 datasheet p. 6: the internal copies are incremented and the alarm is
   checked while the hundredths read 99, and transferred when they roll from 99
   to 00. */
uint64_t Ds1386Clock::NextAlarmCheck() {
    if (check_known_) return check_at_;
    const uint64_t to_minute = (59u - t_.sec) * 100u + (100u - t_.cs);
    uint64_t       check     = at_ + to_minute - 1u;
    Time           minute    = t_;
    minute.cs                = 0u;
    minute.sec               = 0u;
    StepMinute(minute);
    if (check == at_) {
        check += kHundredthsPerMinute;
        StepMinute(minute);
    }
    check_at_ = kNever;
    if (LogicalMasks()) {
        for (uint32_t m = 0; m < kMinutesPerWeek; ++m) {
            if (MinuteMatches(minute)) {
                check_at_ = check;
                break;
            }
            check += kHundredthsPerMinute;
            StepMinute(minute);
        }
    }
    check_known_ = true;
    return check_at_;
}

Ds1386Clock::Advanced Ds1386Clock::Advance(uint64_t hundredth) {
    Advanced r{0u, 0u};
    if (hundredth <= at_) return r;
    for (;;) {
        const uint64_t check = NextAlarmCheck();
        if (check == kNever || check > hundredth) break;
        Step(check - at_);
        check_known_ = false;
        ++r.alarms;
        r.last_alarm = check;
    }
    Step(hundredth - at_);
    return r;
}

Ds1386Clock::Regs Ds1386Clock::Format() const {
    Regs r{};
    r[kRegHundredths]  = Bcd(t_.cs);
    r[kRegSeconds]     = Bcd(t_.sec);
    r[kRegMinutes]     = Bcd(t_.min);
    r[kRegMinuteAlarm] = alarm_[0];
    r[kRegHours]       = HoursReg(t_.hour);
    r[kRegHourAlarm]   = alarm_[1];
    r[kRegDays]        = t_.wday;
    r[kRegDayAlarm]    = alarm_[2];
    r[kRegDate]        = Bcd(t_.date);
    r[kRegMonths]      = Bcd(t_.month);
    r[kRegYears]       = Bcd(t_.year);
    return r;
}

void Ds1386Clock::SetField(uint8_t Time::* field, uint8_t value) {
    t_.*field    = value;
    check_known_ = false;
}

void Ds1386Clock::SetHours(uint8_t hour24, bool hours12) {
    t_.hour      = hour24;
    hours12_     = hours12;
    check_known_ = false;
}

/* DS1386 datasheet p. 6: bits 3, 4, 5 and 6 of register 7 always read 0. */
void Ds1386Clock::SetAlarm(uint32_t which, uint8_t value) {
    alarm_[which] = which == 2u ? static_cast<uint8_t>(value & (kAlarmMask | 0x07u)) : value;
    check_known_  = false;
}

void Ds1386Clock::Save(StateWriter& w) const {
    static_assert(StateVisitCoversAllBytes<Time>([](Time& t, StateFieldBytes& f) { Time::Visit(t, f); }),
                  "Ds1386Clock::Time::Visit must name every field of Time");
    Time            t = t_;
    StateWriteField field(w);
    Time::Visit(t, field);
    w.Write<uint64_t>("ds_at", at_);
    w.Write("ds_hours12", hours12_);
    w.WriteBytes("ds_alarm", alarm_.data(), alarm_.size());
}

void Ds1386Clock::Restore(StateReader& r) {
    StateReadField field(r);
    Time::Visit(t_, field);
    r.Read("ds_at", at_);
    r.Read("ds_hours12", hours12_);
    r.ReadBytes("ds_alarm", alarm_.data(), alarm_.size());
    check_known_ = false;
}
