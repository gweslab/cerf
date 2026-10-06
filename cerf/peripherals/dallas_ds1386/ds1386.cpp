#include "../peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../boards/nec_rockhopper/nec_rockhopper_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/guest_deep_sleep.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../socs/oscillator_ticks.h"
#include "../../state/state_stream.h"
#include "../peripheral_dispatcher.h"
#include "ds1386_clock.h"
#include "ds1386_wiring.h"

#include <algorithm>
#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x1A000000u;
constexpr uint32_t kSize = 0x00010000u;

constexpr uint32_t kRegCommand    = 0xBu;
constexpr uint32_t kRegWatchdogLo = 0xCu;
constexpr uint32_t kRegWatchdogHi = 0xDu;
constexpr uint32_t kRamBase       = 0xEu;

/* DS1386 datasheet p. 9: command register. */
constexpr uint8_t kCmdTe    = 0x80u;
constexpr uint8_t kCmdIpsw  = 0x40u;
constexpr uint8_t kCmdPulse = 0x10u;
constexpr uint8_t kCmdWam   = 0x08u;
constexpr uint8_t kCmdTdm   = 0x04u;
constexpr uint8_t kCmdWaf   = 0x02u;
constexpr uint8_t kCmdTdf   = 0x01u;
constexpr uint8_t kCmdFlags = kCmdWaf | kCmdTdf;

/* DS1386 datasheet p. 9: in pulse mode the output is active for a minimum of
   3 ms, and the flag reads 1 only while it is active. */
constexpr uint64_t kPulseOscTicks = 99u;

/* DS1386 datasheet p. 6: Months bit 7 EOSC (0 runs the oscillator), bit 6 ESQW. */
constexpr uint8_t kMonthEosc  = 0x80u;
constexpr uint8_t kMonthFlags = 0xC0u;

constexpr uint64_t kOscHz = 32768u;
constexpr uint64_t kNever = ~0ull;

using Clock = Ds1386Clock;

class Ds1386Rtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::NecRockhopper;
    }

    void OnReady() override {
        clock_  = &emu_.Get<GuestCycleClock>();
        wiring_ = &emu_.Get<Ds1386Wiring>();
        event_  = clock_->Add([this] { OnEvent(); });
        osc_.Attach(kOscHz, 1u);
        osc_.SetCounting(Running());
        cal_.SeedFromHost(0u);
        ext_ = cal_.Format();
        clock_->RegisterRateListener([this] {
            osc_.Rescale();
            Arm();
        });
        emu_.Get<GuestDeepSleep>().RegisterParkClock([this] { OnEvent(); });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint8_t ReadByte(uint32_t addr) override;
    void    WriteByte(uint32_t addr, uint8_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    bool     Running() const { return (month_flags_ & kMonthEosc) == 0u; }
    uint64_t OscCount() { return osc_.Now(); }
    uint64_t Hundredth() { return Clock::HundredthOf(OscCount()); }

    Clock::Regs TimeRegs() const { return (cmd_ & kCmdTe) != 0u ? cal_.Format() : ext_; }

    uint64_t WatchdogPeriod() const {
        return BcdCalendar::FromBcd(wd_[0]) + BcdCalendar::FromBcd(wd_[1]) * 100u;
    }

    bool TodActive() const { return (cmd_ & kCmdTdf) != 0u && (cmd_ & kCmdTdm) == 0u; }
    bool WdActive() const { return (cmd_ & kCmdWaf) != 0u && (cmd_ & kCmdWam) == 0u; }
    bool WantA() const { return (cmd_ & kCmdIpsw) != 0u ? TodActive() : WdActive(); }
    bool WantB() const { return (cmd_ & kCmdIpsw) != 0u ? WdActive() : TodActive(); }

    void OnEvent() {
        Evaluate();
        Commit(true);
    }

    void Evaluate();
    void Latch(uint8_t flag, uint64_t at_hundredth, uint64_t& pulse_end);
    void EndPulse(uint8_t flag, uint64_t& pulse_end, uint64_t now);
    void ClearFlag(uint8_t flag, uint64_t& pulse_end);
    void Commit(bool deliver);
    void Arm();
    void DriveA(bool level);
    void DriveB(bool level);
    void Freeze(const Clock::Regs& before, uint32_t written);
    void WriteCount(uint32_t reg, uint8_t Clock::Time::* field, const BcdCalendar::Field& f, uint8_t value);
    void WriteHours(uint8_t value);
    void WriteMonth(uint8_t value);
    void WriteCommand(uint8_t value);
    void RestartWatchdog();

    GuestCycleClock*        clock_  = nullptr;
    Ds1386Wiring*           wiring_ = nullptr;
    GuestCycleClock::Event* event_  = nullptr;
    /* DS1386 datasheet p. 3: the internal clock and timers continue to run
       regardless of the level of VCC. */
    StoppableOscillatorTicks osc_{emu_, true};
    Clock                    cal_;
    Clock::Regs              ext_{};

    uint8_t  cmd_         = 0u;
    uint8_t  month_flags_ = kMonthEosc;
    uint8_t  wd_[2]       = {0u, 0u};
    uint64_t wd_start_    = 0u;
    uint64_t wd_eval_     = 0u;
    uint64_t tdf_pulse_   = kNever;
    uint64_t waf_pulse_   = kNever;
    bool     inta_        = false;
    bool     intb_        = false;

    uint8_t nvram_[kSize - kRamBase] = {};
};

void Ds1386Rtc::Evaluate() {
    const uint64_t        h = Hundredth();
    const Clock::Advanced a = cal_.Advance(h);
    if (a.alarms != 0u) Latch(kCmdTdf, a.last_alarm, tdf_pulse_);
    const uint64_t w = WatchdogPeriod();
    if (h > wd_eval_) {
        const uint64_t k = w != 0u ? (h - wd_start_) / w : 0u;
        if (w != 0u && k != (wd_eval_ - wd_start_) / w) Latch(kCmdWaf, wd_start_ + k * w, waf_pulse_);
        wd_eval_ = h;
    }
    const uint64_t p = OscCount();
    EndPulse(kCmdTdf, tdf_pulse_, p);
    EndPulse(kCmdWaf, waf_pulse_, p);
}

void Ds1386Rtc::Latch(uint8_t flag, uint64_t at_hundredth, uint64_t& pulse_end) {
    pulse_end = (cmd_ & kCmdPulse) != 0u ? Clock::OscTickOf(at_hundredth) + kPulseOscTicks : kNever;
    if ((cmd_ & flag) != 0u) return;
    cmd_ |= flag;
    if (flag != kCmdTdf) return;
    const Clock::Regs r = cal_.Format();
    LOG(SocRtc, "DS1386: time-of-day alarm flag set at %02X:%02X:%02X.%02X day %X, command 0x%02X\n",
        r[Clock::kRegHours], r[Clock::kRegMinutes], r[Clock::kRegSeconds],
        r[Clock::kRegHundredths], r[Clock::kRegDays], cmd_);
}

void Ds1386Rtc::EndPulse(uint8_t flag, uint64_t& pulse_end, uint64_t now) {
    if (pulse_end != kNever && now >= pulse_end) ClearFlag(flag, pulse_end);
}

void Ds1386Rtc::ClearFlag(uint8_t flag, uint64_t& pulse_end) {
    cmd_ &= static_cast<uint8_t>(~flag);
    pulse_end = kNever;
}

void Ds1386Rtc::Commit(bool deliver) {
    if (deliver) {
        DriveA(WantA());
        DriveB(WantB());
    } else {
        if (!WantA()) DriveA(false);
        if (!WantB()) DriveB(false);
    }
    Arm();
}

void Ds1386Rtc::Arm() {
    if ((WantA() && !inta_) || (WantB() && !intb_)) {
        clock_->Arm(event_, clock_->Cycles());
        return;
    }
    uint64_t next = kNever;
    if (Running()) {
        if ((cmd_ & (kCmdTdm | kCmdTdf)) == 0u) {
            const uint64_t check = cal_.NextAlarmCheck();
            if (check != Clock::kNever) next = Clock::OscTickOf(check);
        }
        const uint64_t w = WatchdogPeriod();
        if ((cmd_ & (kCmdWam | kCmdWaf)) == 0u && w != 0u) {
            const uint64_t due = wd_start_ + ((Hundredth() - wd_start_) / w + 1u) * w;
            next               = std::min(next, Clock::OscTickOf(due));
        }
        if (TodActive()) next = std::min(next, tdf_pulse_);
        if (WdActive()) next = std::min(next, waf_pulse_);
    }
    if (next == kNever) {
        clock_->Disarm(event_);
        return;
    }
    osc_.ArmAt(event_, next);
}

void Ds1386Rtc::DriveA(bool level) {
    if (level == inta_) return;
    inta_ = level;
    wiring_->SetIntA(level);
}

void Ds1386Rtc::DriveB(bool level) {
    if (level == intb_) return;
    intb_ = level;
    wiring_->SetIntB(level);
}

/* DS1386 datasheet p. 9: with TE = 0 the external clock registers are frozen and
   reads or writes are not affected by updates. */
void Ds1386Rtc::Freeze(const Clock::Regs& before, uint32_t written) {
    if ((cmd_ & kCmdTe) != 0u) return;
    const Clock::Regs after = cal_.Format();
    for (uint32_t i = 0; i < after.size(); ++i) {
        if (i == written || after[i] != before[i]) ext_[i] = after[i];
    }
}

void Ds1386Rtc::WriteCount(uint32_t reg, uint8_t Clock::Time::* field, const BcdCalendar::Field& f,
                           uint8_t value) {
    uint32_t v = 0;
    if (!BcdCalendar::DecodeField(f, value, v)) return;
    const Clock::Regs before = cal_.Format();
    cal_.SetField(field, static_cast<uint8_t>(v));
    Freeze(before, reg);
}

/* DS1386 datasheet p. 6: Hours bit 6 selects 12-hour format, where bit 5 is PM;
   in 24-hour format bit 5 is the second 10-hour bit. */
void Ds1386Rtc::WriteHours(uint8_t value) {
    const bool hours12 = (value & Clock::kHours12) != 0u;
    uint32_t   hour    = 0;
    if (!BcdCalendar::DecodeField(hours12 ? Clock::kHour12 : Clock::kHour24, value, hour)) return;
    if (hours12) hour = (hour == 12u ? 0u : hour) + ((value & Clock::kHoursPm) != 0u ? 12u : 0u);
    const Clock::Regs before = cal_.Format();
    cal_.SetHours(static_cast<uint8_t>(hour), hours12);
    Freeze(before, Clock::kRegHours);
}

void Ds1386Rtc::WriteMonth(uint8_t value) {
    WriteCount(Clock::kRegMonths, &Clock::Time::month, Clock::kMonth, value);
    osc_.SetCounting((value & kMonthEosc) == 0u);
    month_flags_ = value & kMonthFlags;
}

void Ds1386Rtc::WriteCommand(uint8_t value) {
    const uint8_t next = static_cast<uint8_t>((value & ~kCmdFlags) | (cmd_ & kCmdFlags));
    if ((cmd_ & kCmdTe) != 0u && (next & kCmdTe) == 0u) ext_ = cal_.Format();
    cmd_ = next;
}

/* DS1386 datasheet p. 7: any access to register C or D reinitializes the
   countdown from the entered value and clears the flag and the output. */
void Ds1386Rtc::RestartWatchdog() {
    wd_start_ = Hundredth();
    wd_eval_  = wd_start_;
    ClearFlag(kCmdWaf, waf_pulse_);
}

uint8_t Ds1386Rtc::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (off >= kRamBase) return nvram_[off - kRamBase];
    Evaluate();
    uint8_t value = 0;
    switch (off) {
        case Clock::kRegHundredths:
        case Clock::kRegSeconds:
        case Clock::kRegMinutes:
        case Clock::kRegHours:
        case Clock::kRegDays:
        case Clock::kRegDate:
        case Clock::kRegYears:
            return TimeRegs()[off];
        case Clock::kRegMonths:
            return static_cast<uint8_t>(TimeRegs()[off] | month_flags_);
        case kRegCommand:
            return cmd_;
        /* DS1386 datasheet p. 6: the flag and interrupt are cleared when the
           alarm registers are read or written. */
        case Clock::kRegMinuteAlarm:
        case Clock::kRegHourAlarm:
        case Clock::kRegDayAlarm:
            value = cal_.Format()[off];
            ClearFlag(kCmdTdf, tdf_pulse_);
            break;
        case kRegWatchdogLo:
        case kRegWatchdogHi:
            value = wd_[off - kRegWatchdogLo];
            RestartWatchdog();
            break;
        default:
            HaltUnsupportedAccess("ReadByte", addr, 0);
    }
    Commit(false);
    return value;
}

void Ds1386Rtc::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kBase;
    if (off >= kRamBase) {
        nvram_[off - kRamBase] = value;
        return;
    }
    Evaluate();
    switch (off) {
        case Clock::kRegHundredths: WriteCount(off, &Clock::Time::cs, Clock::kCs, value); break;
        case Clock::kRegSeconds:    WriteCount(off, &Clock::Time::sec, Clock::kSec, value); break;
        case Clock::kRegMinutes:    WriteCount(off, &Clock::Time::min, Clock::kMin, value); break;
        case Clock::kRegHours:      WriteHours(value); break;
        case Clock::kRegDays:       WriteCount(off, &Clock::Time::wday, Clock::kWday, value); break;
        case Clock::kRegDate:       WriteCount(off, &Clock::Time::date, Clock::kDate, value); break;
        case Clock::kRegMonths:     WriteMonth(value); break;
        case Clock::kRegYears:      WriteCount(off, &Clock::Time::year, Clock::kYear, value); break;
        case Clock::kRegMinuteAlarm:
        case Clock::kRegHourAlarm:
        case Clock::kRegDayAlarm:
            cal_.SetAlarm((off - Clock::kRegMinuteAlarm) / 2u, value);
            ClearFlag(kCmdTdf, tdf_pulse_);
            break;
        case kRegCommand: WriteCommand(value); break;
        case kRegWatchdogLo:
        case kRegWatchdogHi:
            wd_[off - kRegWatchdogLo] = value;
            RestartWatchdog();
            break;
        default: HaltUnsupportedAccess("WriteByte", addr, value);
    }
    Commit(false);
}

void Ds1386Rtc::SaveState(StateWriter& w) {
    osc_.Save(w);
    cal_.Save(w);
    w.WriteBytes("ds_ext", ext_.data(), ext_.size());
    w.Write("ds_cmd", cmd_);
    w.Write("ds_month_flags", month_flags_);
    w.WriteBytes("ds_watchdog", wd_, 2u);
    w.Write<uint64_t>("ds_wd_start", wd_start_);
    w.Write<uint64_t>("ds_wd_eval", wd_eval_);
    w.Write<uint64_t>("ds_tdf_pulse", tdf_pulse_);
    w.Write<uint64_t>("ds_waf_pulse", waf_pulse_);
    w.Write("ds_inta", inta_);
    w.Write("ds_intb", intb_);
    w.WriteBytes("nvram", nvram_, sizeof(nvram_));
}

void Ds1386Rtc::RestoreState(StateReader& r) {
    osc_.Restore(r);
    cal_.Restore(r);
    r.ReadBytes("ds_ext", ext_.data(), ext_.size());
    r.Read("ds_cmd", cmd_);
    r.Read("ds_month_flags", month_flags_);
    r.ReadBytes("ds_watchdog", wd_, 2u);
    r.Read("ds_wd_start", wd_start_);
    r.Read("ds_wd_eval", wd_eval_);
    r.Read("ds_tdf_pulse", tdf_pulse_);
    r.Read("ds_waf_pulse", waf_pulse_);
    r.Read("ds_inta", inta_);
    r.Read("ds_intb", intb_);
    r.ReadBytes("nvram", nvram_, sizeof(nvram_));
    clock_->Disarm(event_);
}

void Ds1386Rtc::PostRestore() {
    wiring_->SetIntA(inta_);
    wiring_->SetIntB(intb_);
    Arm();
}

}

REGISTER_SERVICE(Ds1386Rtc);
