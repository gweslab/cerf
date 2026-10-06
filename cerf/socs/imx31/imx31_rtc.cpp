#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../host/guest_deep_sleep.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../oscillator_ticks.h"
#include "imx31_avic.h"
#include "imx31_ccm.h"
#include "imx31_id.h"
#include "imx31_rtc_counter.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x53FD8000u;
constexpr uint32_t kSize = 0x00004000u;

/* MCIMX31RM Table 36-1. */
constexpr uint32_t kOffHourMin  = 0x00u;
constexpr uint32_t kOffSeconds  = 0x04u;
constexpr uint32_t kOffAlrmHm   = 0x08u;
constexpr uint32_t kOffAlrmSec  = 0x0Cu;
constexpr uint32_t kOffRtcctl   = 0x10u;
constexpr uint32_t kOffRtcisr   = 0x14u;
constexpr uint32_t kOffRtcienr  = 0x18u;
constexpr uint32_t kOffStpwch   = 0x1Cu;
constexpr uint32_t kOffDayr     = 0x20u;
constexpr uint32_t kOffDayalarm = 0x24u;

/* MCIMX31RM Table 36-8 and Figure 36-7 (reset 0x80). */
constexpr uint32_t kCtlEn       = 1u << 7;
constexpr uint32_t kCtlXtlShift = 5u;
constexpr uint32_t kCtlXtlMask  = 3u << kCtlXtlShift;
constexpr uint32_t kCtlGen      = 1u << 1;
constexpr uint32_t kCtlSwr      = 1u << 0;
constexpr uint32_t kCtlReset    = kCtlEn;

constexpr uint32_t kHourShift  = 8u;
constexpr uint32_t kHourMask   = 0x1Fu;
constexpr uint32_t kMinuteMask = 0x3Fu;
constexpr uint32_t kSecondMask = 0x3Fu;
constexpr uint32_t kDayMask    = 0xFFFFu;
constexpr uint32_t kCountMask  = 0x3Fu;
constexpr uint32_t kMaxHour    = 23u;
constexpr uint32_t kMaxMinute  = 59u;
constexpr uint32_t kMaxSecond  = 59u;

/* MCIMX31RM Table 2-3: interrupt 25 is the RTC. */
constexpr uint32_t kAvicSource = 25u;

/* MCIMX31RM Table 36-8 XTL: 00 and 11 32.768 kHz, 01 32 kHz, 10 38.4 kHz. */
uint64_t XtlDivisor(uint32_t ctl) {
    switch ((ctl & kCtlXtlMask) >> kCtlXtlShift) {
        case 1u: return 32000u;
        case 2u: return 38400u;
        default: return 32768u;
    }
}

class Imx31Rtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Imx31;
    }

    void OnReady() override {
        clock_ = &emu_.Get<GuestCycleClock>();
        avic_  = &emu_.Get<Imx31Avic>();
        event_ = clock_->Add([this] { OnEvent(); });
        osc_.Attach(emu_.Get<Imx31Ccm>().CkilHz(), 1u);
        counter_.SetDivisor(XtlDivisor(ctl_));
        UpdateAlarm();
        clock_->RegisterRateListener([this] {
            osc_.Rescale();
            Arm();
        });
        emu_.Get<GuestDeepSleep>().RegisterParkClock([this] { OnEvent(); });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { ResetLine(); });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    bool     Running() const { return (ctl_ & kCtlEn) != 0u; }
    uint64_t Prescaler() { return osc_.Now(); }

    void Evaluate() { latched_ |= counter_.Advance(Prescaler()); }

    void OnEvent() {
        Evaluate();
        Commit(true);
    }

    void Commit(bool deliver);
    void Arm();
    void DriveLine(bool level);
    void UpdateAlarm();
    void WriteControl(uint32_t value);
    void ApplyDivisor(uint64_t ref_per_second);
    void WriteTime(uint32_t off, uint32_t value);
    void SoftReset();
    void ResetLine();

    GuestCycleClock*        clock_ = nullptr;
    Imx31Avic*              avic_  = nullptr;
    GuestCycleClock::Event* event_ = nullptr;
    StoppableOscillatorTicks osc_{emu_, true};
    Imx31RtcCounter          counter_;

    uint32_t ctl_      = kCtlReset;
    uint32_t ienr_     = 0u;
    uint32_t latched_  = 0u;
    uint32_t alrm_hm_  = 0u;
    uint32_t alrm_sec_ = 0u;
    uint32_t dayalarm_ = 0u;
    bool     line_     = false;
};

uint32_t Imx31Rtc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    Evaluate();
    const uint64_t s = counter_.Seconds(Prescaler());
    switch (off) {
        case kOffHourMin: {
            const uint64_t tod = s % Imx31RtcCounter::kSecondsPerDay;
            return static_cast<uint32_t>(((tod / 3600u) << kHourShift) | ((tod % 3600u) / 60u));
        }
        case kOffSeconds:  return static_cast<uint32_t>(s % 60u);
        case kOffAlrmHm:   return alrm_hm_;
        case kOffAlrmSec:  return alrm_sec_;
        case kOffRtcctl:   return ctl_;
        case kOffRtcisr:   return latched_;
        case kOffRtcienr:  return ienr_;
        case kOffStpwch:   return counter_.Stopwatch();
        case kOffDayr:     return static_cast<uint32_t>(s / Imx31RtcCounter::kSecondsPerDay);
        case kOffDayalarm: return dayalarm_;
        default:           break;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Imx31Rtc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    Evaluate();
    switch (off) {
        case kOffHourMin:
        case kOffSeconds:
        case kOffDayr:
            WriteTime(off, value);
            break;
        case kOffAlrmHm:
            alrm_hm_ = value & ((kHourMask << kHourShift) | kMinuteMask);
            UpdateAlarm();
            break;
        case kOffAlrmSec:
            alrm_sec_ = value & kSecondMask;
            UpdateAlarm();
            break;
        case kOffDayalarm:
            dayalarm_ = value & kDayMask;
            UpdateAlarm();
            break;
        case kOffRtcctl:  WriteControl(value); break;
        case kOffRtcisr:  latched_ &= ~(value & Imx31RtcCounter::kSources); break;
        case kOffRtcienr: ienr_ = value & Imx31RtcCounter::kSources; break;
        case kOffStpwch:  counter_.SetStopwatch(static_cast<uint8_t>(value & kCountMask)); break;
        default:          HaltUnsupportedAccess("WriteWord", addr, value);
    }
    Commit(false);
}

void Imx31Rtc::WriteTime(uint32_t off, uint32_t value) {
    const uint64_t p   = Prescaler();
    const uint64_t s   = counter_.Seconds(p);
    uint64_t       day = s / Imx31RtcCounter::kSecondsPerDay;
    uint64_t       tod = s % Imx31RtcCounter::kSecondsPerDay;
    uint32_t hour = static_cast<uint32_t>(tod / 3600u);
    uint32_t min  = static_cast<uint32_t>((tod % 3600u) / 60u);
    uint32_t sec  = static_cast<uint32_t>(tod % 60u);
    if (off == kOffHourMin) {
        hour = (value >> kHourShift) & kHourMask;
        min  = value & kMinuteMask;
    } else if (off == kOffSeconds) {
        sec = value & kSecondMask;
    } else {
        day = value & kDayMask;
    }
    counter_.SetSeconds(p, day * Imx31RtcCounter::kSecondsPerDay + hour * 3600u + min * 60u + sec);
}

void Imx31Rtc::WriteControl(uint32_t value) {
    if ((value & kCtlSwr) != 0u) SoftReset();
    ApplyDivisor(XtlDivisor(value));
    osc_.SetCounting((value & kCtlEn) != 0u);
    ctl_ = value & (kCtlEn | kCtlXtlMask | kCtlGen);
}

void Imx31Rtc::ApplyDivisor(uint64_t ref_per_second) {
    if (ref_per_second == counter_.Divisor()) return;
    const uint64_t p = Prescaler();
    const uint64_t s = counter_.Seconds(p);
    counter_.SetDivisor(ref_per_second);
    counter_.SetSeconds(p, s);
}

/* MCIMX31RM Table 36-8 SWR: "Resets the module to its default state. However, a software reset
   will have no effect on the RTC enable (EN) bit." */
void Imx31Rtc::SoftReset() {
    ctl_      &= kCtlEn;
    ApplyDivisor(XtlDivisor(ctl_));
    ienr_      = 0u;
    latched_   = 0u;
    alrm_hm_   = 0u;
    alrm_sec_  = 0u;
    dayalarm_  = 0u;
    UpdateAlarm();
    counter_.SetStopwatch(0u);
}

/* MCIMX31RM §3.6.1: ccm_pll_reset2 drives the RTC; Figure 3-42 asserts it with periph_reset_out. */
void Imx31Rtc::ResetLine() {
    Evaluate();
    osc_.SetCounting(true);
    SoftReset();
    ctl_ = kCtlReset;
    Commit(false);
}

void Imx31Rtc::UpdateAlarm() {
    const uint32_t hour  = (alrm_hm_ >> kHourShift) & kHourMask;
    const uint32_t min   = alrm_hm_ & kMinuteMask;
    const bool     valid = hour <= kMaxHour && min <= kMaxMinute && alrm_sec_ <= kMaxSecond;
    counter_.SetAlarm(valid, static_cast<uint64_t>(dayalarm_) * Imx31RtcCounter::kSecondsPerDay +
                                 hour * 3600u + min * 60u + alrm_sec_);
}

void Imx31Rtc::Commit(bool deliver) {
    const bool want = (latched_ & ienr_) != 0u;
    if (deliver)    DriveLine(want);
    else if (!want) DriveLine(false);
    Arm();
}

void Imx31Rtc::Arm() {
    if ((latched_ & ienr_) != 0u) {
        if (line_) clock_->Disarm(event_);
        else       clock_->Arm(event_, clock_->Cycles());
        return;
    }
    const uint32_t sources = ienr_ & Imx31RtcCounter::kSources;
    const uint64_t next    = Running() ? counter_.NextEvent(sources) : Imx31RtcCounter::kNever;
    if (next == Imx31RtcCounter::kNever) {
        clock_->Disarm(event_);
        return;
    }
    osc_.ArmAt(event_, next);
}

void Imx31Rtc::DriveLine(bool level) {
    if (level == line_) return;
    line_ = level;
    if (level) avic_->AssertSource(kAvicSource);
    else       avic_->DeassertSource(kAvicSource);
}

void Imx31Rtc::SaveState(StateWriter& w) {
    osc_.Save(w);
    w.Write("rtc_ctl", ctl_);
    w.Write("rtc_ienr", ienr_);
    w.Write("rtc_isr", latched_);
    w.Write("rtc_alrm_hm", alrm_hm_);
    w.Write("rtc_alrm_sec", alrm_sec_);
    w.Write("rtc_dayalarm", dayalarm_);
    w.Write<uint8_t>("rtc_line", line_ ? 1u : 0u);
    counter_.Save(w);
}

void Imx31Rtc::RestoreState(StateReader& r) {
    osc_.Restore(r);
    r.Read("rtc_ctl", ctl_);
    r.Read("rtc_ienr", ienr_);
    r.Read("rtc_isr", latched_);
    r.Read("rtc_alrm_hm", alrm_hm_);
    r.Read("rtc_alrm_sec", alrm_sec_);
    r.Read("rtc_dayalarm", dayalarm_);
    uint8_t line = 0u;
    r.Read("rtc_line", line);
    line_ = line != 0u;
    counter_.SetDivisor(XtlDivisor(ctl_));
    UpdateAlarm();
    counter_.Restore(r);
    clock_->Disarm(event_);
}

void Imx31Rtc::PostRestore() {
    if (line_) avic_->AssertSource(kAvicSource);
    else       avic_->DeassertSource(kAvicSource);
    Arm();
}

}

REGISTER_SERVICE(Imx31Rtc);
