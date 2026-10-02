#include "rtc8564_calendar.h"
#include "rtc8564_core.h"
#include "rtc8564_registers.h"
#include "rtc8564_wiring.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../core/tick_scale.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <mutex>

namespace {

using namespace Rtc8564Regs;

constexpr uint8_t kControl2Writable = kTie | kAie | kTf | kAf | kTiTp;
constexpr uint8_t kControl2Fixed = 0xA0u;
constexpr uint8_t kTimerEnable = 0x80u;
constexpr uint8_t kTimerFrequencyMask = 0x03u;
constexpr uint8_t kClkoutEnable = 0x80u;

/* Epson RTC-8564 MQ322-04 sections 8.1 and 8.2.1-8.2.5 (pp. 5-7): the bits
   each register holds; ETM11J-07 section 13.1.3 item 4 (p. 14): any write to
   Seconds clears VL. */
constexpr uint8_t kStoredBits[16] = {
    kStop, kControl2Writable, 0x7Fu, 0x7Fu, 0x3Fu, 0x3Fu, 0x07u, 0x9Fu,
    0xFFu, 0xFFu, 0xBFu, 0xBFu, 0x87u, 0x83u, kTimerEnable | kTimerFrequencyMask, 0xFFu,
};

class Rtc8564 final : public Rtc8564Core {
public:
    using Rtc8564Core::Rtc8564Core;

    bool ShouldRegister() override { return emu_.TryGet<Rtc8564Wiring>() != nullptr; }

    void OnReady() override {
        clock_       = &emu_.Get<GuestCycleClock>();
        cpu_hz_      = clock_->CpuHz();
        timer_event_ = clock_->Add([this] { OnClockEvent(); });
        pulse_event_ = clock_->Add([this] { OnClockEvent(); });
        alarm_event_ = clock_->Add([this] { OnClockEvent(); });
        clock_->RegisterRateListener([this] { OnRateChange(); });
        std::lock_guard<std::mutex> guard(mutex_);
        const uint64_t now = clock_->Cycles();
        SeedCalendar(now);
        const Rtc8564Wiring::Retained retained = emu_.Get<Rtc8564Wiring>().RetainedRegisters();
        WriteRegister(kControl2, retained.control2, now);
        for (uint8_t i = 0; i < 4u; ++i) WriteRegister(static_cast<uint8_t>(0x09u + i), retained.alarm[i], now);
        WriteRegister(0x0Du, retained.clkout, now);
        WriteRegister(kTimer, retained.timer, now);
        WriteRegister(kTimerControl, retained.timer_control, now);
        calendar_.Materialize(registers_);
        calendar_.EvaluateAlarm(registers_);
        Rearm(now);
    }

    void OnShutdown() override {
        std::lock_guard<std::mutex> guard(mutex_);
        SetInterrupt(false);
    }

    void Update() override {
        std::lock_guard<std::mutex> guard(mutex_);
        Service(clock_->Cycles());
    }

    void WriteAt(uint8_t index, uint8_t value) override {
        std::lock_guard<std::mutex> guard(mutex_);
        const uint64_t now = clock_->Cycles();
        Materialize(now);
        WriteRegister(index, value, now);
        Service(now);
    }

    /* Epson RTC-8564 ETM11J-07 section 13.1.8 (p. 16) and section 13.2.2
       (p. 21): reading the timer register shows the count during operation;
       TE 1 to 0 makes the count and the preset invalid. */
    uint8_t ReadAt(uint8_t index) override {
        std::lock_guard<std::mutex> guard(mutex_);
        index &= 0x0Fu;
        if (index == kTimer && !TimerRunning()) {
            emu_.Get<Fatal>().Die("RTC8564: read of the timer register with TE = 0 (timer "
                                  "control 0x%02X)", registers_[kTimerControl]);
        }
        const uint64_t now = clock_->Cycles();
        Materialize(now);
        const uint8_t value = registers_[index];
        Service(now);
        return value;
    }

    bool StopSet() override {
        std::lock_guard<std::mutex> guard(mutex_);
        return Stopped();
    }

    void SaveState(StateWriter& writer) override;
    void RestoreState(StateReader& reader) override;

    void PostRestore() override {
        std::lock_guard<std::mutex> guard(mutex_);
        const bool restored_asserted = interrupt_asserted_;
        interrupt_asserted_ = !restored_asserted;
        SetInterrupt(restored_asserted);
        Service(clock_->Cycles());
    }

private:
    [[noreturn]] void RatioOverflow() const {
        emu_.Get<Fatal>().Die("RTC8564: the %llu Hz CPU clock overflows the cycle ratio",
                              static_cast<unsigned long long>(cpu_hz_));
    }

    void SeedCalendar(uint64_t now) {
        int host_year = 0;
        if (!calendar_.SeedFromHost(cpu_hz_, now, emu_.Get<Rtc8564Wiring>().CalendarYearBase(),
                                    host_year)) {
            emu_.Get<Fatal>().Die("RTC8564: host year %d is outside the calendar range of this "
                                  "board, or the CPU clock overflows the cycle ratio", host_year);
        }
    }

    bool Stopped() const { return (registers_[kControl1] & kStop) != 0; }

    void Materialize(uint64_t now) {
        if (Stopped()) {
            registers_[kTimer] = TimerRunning() ? static_cast<uint8_t>(timer_left_) : preset_;
            return;
        }
        calendar_.Advance(now, registers_);
        calendar_.Materialize(registers_);
        MaterializeTimer(now);
    }

    void Service(uint64_t now) {
        Materialize(now);
        UpdateInterrupt(now);
        Rearm(now);
    }

    void OnClockEvent() {
        std::lock_guard<std::mutex> guard(mutex_);
        Service(clock_->Cycles());
    }

    void WriteControl1(uint8_t value, uint64_t now);
    void WriteTimerControl(uint8_t value, uint64_t now);
    void WriteTimer(uint8_t value);
    void WriteRegister(uint8_t index, uint8_t value, uint64_t now);

    bool TimerRunning() const { return (registers_[kTimerControl] & kTimerEnable) != 0; }

    uint8_t SourceSelect() const { return registers_[kTimerControl] & kTimerFrequencyMask; }

    uint64_t TimerLeft(uint64_t now) const {
        return Stopped() ? timer_left_ : timer_next_ - calendar_.SourceTicks(SourceSelect(), now);
    }

    void SetTimerLeft(uint64_t now, uint64_t left) {
        timer_left_ = left;
        if (!Stopped()) timer_next_ = calendar_.SourceTicks(SourceSelect(), now) + left;
    }

    /* Epson RTC-8564 ETM11J-07 section 13.2.2 (p. 21) items 4-5: while TE = 1 the
       countdown, the event and the preset reload repeat in either mode; section
       13.2.1 (p. 18): in level mode TF and /INT hold until TF is written 0. */
    void MaterializeTimer(uint64_t now) {
        if (!TimerRunning()) {
            registers_[kTimer] = preset_;
            return;
        }
        const uint8_t  td = SourceSelect();
        const uint64_t k  = calendar_.SourceTicks(td, now);
        if (k >= timer_next_) {
            const uint64_t n    = preset_;
            const uint64_t last = timer_next_ + (k - timer_next_) / n * n;
            timer_next_ = last + n;
            registers_[kControl2] |= kTf;
            if (TimerInterruptEnabled() && RepeatedTimerMode())
                pulse_end_ = calendar_.CycleOfSourceTick(td, last) + PulseCycles();
        }
        registers_[kTimer] = static_cast<uint8_t>(timer_next_ - k);
    }

    bool TimerInterruptEnabled() const { return (registers_[kControl2] & kTie) != 0; }

    bool AlarmInterruptEnabled() const { return (registers_[kControl2] & kAie) != 0; }

    bool RepeatedTimerMode() const { return (registers_[kControl2] & kTiTp) != 0; }

    bool LevelInterruptActive() const {
        const bool alarm = (registers_[kControl2] & (kAf | kAie)) == (kAf | kAie);
        const bool timer = !RepeatedTimerMode() && (registers_[kControl2] & (kTf | kTie)) == (kTf | kTie);
        return alarm || timer;
    }

    /* Epson RTC-8564 ETM11J-07 section 13.2.2 (p. 20): /INT auto recovery time
       tRTN in repeated interrupt mode, by source clock, for preset n = 1 and
       1 < n. */
    uint64_t PulseCycles() const {
        const bool n_is_one = preset_ == 1u;
        uint64_t   den      = 64u;
        switch (SourceSelect()) {
        case 0: den = n_is_one ? 8192u : 4096u; break;
        case 1: den = n_is_one ? 128u : 64u; break;
        default: break;
        }
        return ScaleU64Ceil(cpu_hz_, 1u, den);
    }

    /* Epson RTC-8564 ETM11J-07 section 13.2.2 (p. 21) and section 13.3.2
       (p. 26): writing 0 clears TF or AF; writing 1 is invalid. */
    void WriteControl2(uint8_t value) {
        if ((value & kControl2Fixed) != 0u) {
            emu_.Get<Fatal>().Die("RTC8564: Control2 write 0x%02X sets a fixed-0 bit", value);
        }
        const uint8_t flags = registers_[kControl2] & (kTf | kAf);
        const uint8_t requested = value & kControl2Writable;
        uint8_t next = requested & ~(kTf | kAf);
        if ((requested & kTf) && (flags & kTf)) next |= kTf;
        if ((requested & kAf) && (flags & kAf)) next |= kAf;
        registers_[kControl2] = next;
        /* NXP PCF8563 Rev. 10 Fig 6 (p. 9): the interface's clear TF also clears
           PULSE GENERATOR 2. */
        if ((requested & kTf) == 0u) {
            pulse_end_  = 0;
            pulse_held_ = 0;
        }
    }

    void Rearm(uint64_t now) {
        const bool tf_latched = (registers_[kControl2] & kTf) != 0u;
        if (TimerRunning() && !Stopped() && TimerInterruptEnabled() &&
            (RepeatedTimerMode() || !tf_latched))
            clock_->Arm(timer_event_, calendar_.CycleOfSourceTick(SourceSelect(), timer_next_));
        else
            clock_->Disarm(timer_event_);
        if (pulse_end_ > now)
            clock_->Arm(pulse_event_, pulse_end_);
        else
            clock_->Disarm(pulse_event_);
        bool alarm_armed = false;
        if (!Stopped() && AlarmInterruptEnabled() && (registers_[kControl2] & kAf) == 0u) {
            if (!alarm_known_ || (alarm_has_due_ && alarm_due_ <= now)) {
                alarm_has_due_ = calendar_.NextAlarmCycle(registers_, alarm_due_);
                alarm_known_   = true;
            }
            alarm_armed = alarm_has_due_;
        }
        if (alarm_armed)
            clock_->Arm(alarm_event_, alarm_due_);
        else
            clock_->Disarm(alarm_event_);
    }

    void OnRateChange() {
        std::lock_guard<std::mutex> guard(mutex_);
        const uint64_t now    = clock_->Cycles();
        const uint64_t new_hz = clock_->CpuHz();
        Materialize(now);
        const bool     live = TimerRunning();
        const uint64_t left = live ? TimerLeft(now) : 0u;
        if (!Stopped() && !calendar_.Rescale(now, new_hz, registers_)) RatioOverflow();
        if (pulse_end_ > now) pulse_end_ = now + ScaleU64Ceil(pulse_end_ - now, new_hz, cpu_hz_);
        if (pulse_held_ != 0u) pulse_held_ = ScaleU64Ceil(pulse_held_, new_hz, cpu_hz_);
        cpu_hz_       = new_hz;
        alarm_known_  = false;
        if (live) SetTimerLeft(now, left);
        UpdateInterrupt(now);
        Rearm(now);
    }

    /* Epson RTC-8564 ETM11J-07 sections 13.2.1 (p. 18), 13.2.2 (p. 22) and
       13.4 (p. 28): /INT is shared by the timer and alarm; a repeated-mode
       event holds it low for tRTN, and TIE = 0 releases the timer's /INT. */
    void UpdateInterrupt(uint64_t now) {
        if (pulse_end_ != 0 && now >= pulse_end_) pulse_end_ = 0;
        const bool pulse = pulse_end_ != 0 || pulse_held_ != 0;
        SetInterrupt((pulse && TimerInterruptEnabled()) || LevelInterruptActive());
    }

    void SetInterrupt(bool active) {
        if (active == interrupt_asserted_) return;
        interrupt_asserted_ = active;
        emu_.Get<Rtc8564Wiring>().SetInterrupt(active);
    }

    GuestCycleClock*        clock_       = nullptr;
    GuestCycleClock::Event* timer_event_ = nullptr;
    GuestCycleClock::Event* pulse_event_ = nullptr;
    GuestCycleClock::Event* alarm_event_ = nullptr;
    Rtc8564Calendar         calendar_;
    uint64_t                cpu_hz_     = 1;
    uint64_t                timer_next_ = 0;
    uint64_t                timer_left_ = 0;
    uint64_t                pulse_end_  = 0;
    uint64_t                pulse_held_ = 0;
    uint64_t                alarm_due_  = 0;
    bool                    alarm_has_due_ = false;
    bool                    alarm_known_   = false;
    Rtc8564Regs::File       registers_{};
    uint8_t                 preset_ = 0;
    bool                    preset_invalid_ = false;
    std::mutex              mutex_;
    bool                    interrupt_asserted_ = false;
};

/* Epson RTC-8564 ETM11J-07 section 13.1.1 (p. 12): STOP = 1 stops the clock,
   calendar, alarm and timer; the TEST bits and the fixed bits are written 0. */
void Rtc8564::WriteControl1(uint8_t value, uint64_t now) {
    if ((value & ~kStop) != 0u) {
        emu_.Get<Fatal>().Die("RTC8564: Control1 write 0x%02X sets a TEST or fixed-0 bit", value);
    }
    const bool was_stopped = Stopped();
    /* Epson MQ322-04 section 8.2.1 (p. 5): STOP = 1 puts all internal count down
       chain in the zero clear state; NXP PCF8563 Rev. 10 section 8.3.2.1 (p. 9):
       the countdown pulse generator uses an internal clock. */
    if (!was_stopped && (value & kStop)) {
        if (TimerRunning()) timer_left_ = TimerLeft(now);
        if (pulse_end_ > now) pulse_held_ = pulse_end_ - now;
        pulse_end_ = 0;
    }
    registers_[kControl1] = value;
    if (!was_stopped || Stopped()) return;
    Rtc8564Calendar::Time t;
    if (!Rtc8564Calendar::Parse(registers_, t)) {
        emu_.Get<Fatal>().Die("RTC8564: STOP released on an impossible time (regs 02-08 = %02X "
                              "%02X %02X %02X %02X %02X %02X)", registers_[kSeconds],
                              registers_[kMinutes], registers_[kHours], registers_[kDays],
                              registers_[kWeekdays], registers_[kMonths], registers_[kYears]);
    }
    LOG(SocRtc, "RTC8564: STOP released at %02u:%02u:%02u day %u month %u year %u weekday %u\n",
        t.hour, t.min, t.sec, t.day, t.month, t.year, t.wday);
    if (!calendar_.Load(cpu_hz_, now, t, 1u, 2u)) RatioOverflow();
    calendar_.EvaluateAlarm(registers_);
    if (TimerRunning()) SetTimerLeft(now, timer_left_);
    if (pulse_held_ != 0u) {
        pulse_end_  = now + pulse_held_;
        pulse_held_ = 0;
    }
}

/* Epson RTC-8564 ETM11J-07 sections 13.1.7 (p. 16) and 13.2.2 (pp. 20-21):
   the preset is written with TE = 0, TE = 1 starts the countdown and TE = 0
   stops it and invalidates the count and the preset. */
void Rtc8564::WriteTimerControl(uint8_t value, uint64_t now) {
    const bool running = TimerRunning();
    const bool enable  = (value & kTimerEnable) != 0;
    if (running && enable) {
        emu_.Get<Fatal>().Die("RTC8564: timer control write 0x%02X while the timer runs", value);
    }
    if (!running && enable && (preset_invalid_ || preset_ == 0u)) {
        emu_.Get<Fatal>().Die("RTC8564: timer control write 0x%02X sets TE without a valid "
                              "preset", value);
    }
    registers_[kTimerControl] = value & kStoredBits[kTimerControl];
    if (running && !enable) {
        preset_invalid_ = true;
        return;
    }
    if (enable) SetTimerLeft(now, preset_);
}

/* ETM11J-07 section 13.1.8 (p. 16): the preset is 01h to FFh. */
void Rtc8564::WriteTimer(uint8_t value) {
    if (TimerRunning()) {
        emu_.Get<Fatal>().Die("RTC8564: timer register write 0x%02X while TE = 1", value);
    }
    if (value == 0u) emu_.Get<Fatal>().Die("RTC8564: timer register write of preset 00h");
    preset_         = value;
    preset_invalid_ = false;
}

void Rtc8564::WriteRegister(uint8_t index, uint8_t value, uint64_t now) {
    index &= 0x0Fu;
    alarm_known_ = false;
    if (index >= kSeconds && index <= kYears && !Stopped()) {
        emu_.Get<Fatal>().Die("RTC8564: write 0x%02X to time register 0x%02X with STOP "
                              "clear; a running time write is not modelled", value, index);
    }
    switch (index) {
    case kControl1: WriteControl1(value, now); return;
    case kControl2: WriteControl2(value); return;
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x0C:
        registers_[index] = value & kStoredBits[index];
        if (!Stopped()) calendar_.EvaluateAlarm(registers_);
        return;
    case 0x0D:
        if (value & kClkoutEnable) {
            emu_.Get<Fatal>().Die("RTC8564: CLKOUT write 0x%02X sets FE; the CLKOUT pin is not "
                                  "modelled", value);
        }
        registers_[index] = value & kStoredBits[index];
        return;
    case kTimerControl: WriteTimerControl(value, now); return;
    case kTimer: WriteTimer(value); return;
    default: registers_[index] = value & kStoredBits[index]; return;
    }
}

void Rtc8564::SaveState(StateWriter& writer) {
    std::lock_guard<std::mutex> guard(mutex_);
    const uint64_t                now = clock_->Cycles();
    Materialize(now);
    const uint64_t pulse_left = Stopped() ? pulse_held_ : pulse_end_ > now ? pulse_end_ - now : 0u;
    calendar_.SaveState(writer, now, Stopped());
    writer.Write("preset", preset_);
    writer.Write("preset_invalid", preset_invalid_);
    writer.Write<uint64_t>("timer_ticks_left", TimerRunning() ? TimerLeft(now) : 0u);
    writer.Write<int64_t>("pulse_remaining_ns", clock_->CyclesToNs(pulse_left));
    writer.Write("interrupt_asserted", interrupt_asserted_);
    writer.WriteBytes("registers", registers_.data(), registers_.size());
}

void Rtc8564::RestoreState(StateReader& reader) {
    std::lock_guard<std::mutex> guard(mutex_);
    const uint64_t now = clock_->Cycles();
    int64_t        pulse_ns   = 0;
    uint64_t       ticks_left = 0;
    cpu_hz_ = clock_->CpuHz();
    calendar_.RestoreState(reader, cpu_hz_, now);
    reader.Read("preset", preset_);
    reader.Read("preset_invalid", preset_invalid_);
    reader.Read("timer_ticks_left", ticks_left);
    reader.Read("pulse_remaining_ns", pulse_ns);
    reader.Read("interrupt_asserted", interrupt_asserted_);
    reader.ReadBytes("registers", registers_.data(), registers_.size());
    timer_next_ = 0;
    timer_left_ = 0;
    if (TimerRunning()) SetTimerLeft(now, ticks_left);
    const uint64_t pulse_left = pulse_ns != 0 ? clock_->NsToCycles(pulse_ns) : 0u;
    pulse_held_  = Stopped() ? pulse_left : 0u;
    pulse_end_   = !Stopped() && pulse_left != 0u ? now + pulse_left : 0u;
    alarm_known_ = false;
    Rearm(now);
}

REGISTER_SERVICE_AS(Rtc8564, Rtc8564Core);

} // namespace
