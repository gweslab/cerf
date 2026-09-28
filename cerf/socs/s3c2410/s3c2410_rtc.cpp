#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../core/tick_scale.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../host/guest_deep_sleep.h"
#include "../../jit/guest_engine.h"
#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"
#include "../oscillator_ticks.h"
#include "s3c2410_rtc_alarm.h"
#include "s3c2410_rtc_calendar.h"

#include <cstdint>

namespace {

constexpr uint32_t kOffRtcCon  = 0x40u;
constexpr uint32_t kOffTicnt   = 0x44u;
constexpr uint32_t kOffRtcAlm  = 0x50u;
constexpr uint32_t kOffAlmSec  = 0x54u;
constexpr uint32_t kOffAlmMin  = 0x58u;
constexpr uint32_t kOffAlmHour = 0x5Cu;
constexpr uint32_t kOffAlmDate = 0x60u;
constexpr uint32_t kOffAlmMon  = 0x64u;
constexpr uint32_t kOffAlmYear = 0x68u;
constexpr uint32_t kOffRtcRst  = 0x6Cu;
constexpr uint32_t kOffBcdSec  = 0x70u;
constexpr uint32_t kOffBcdMin  = 0x74u;
constexpr uint32_t kOffBcdHour = 0x78u;
constexpr uint32_t kOffBcdDate = 0x7Cu;
constexpr uint32_t kOffBcdDay  = 0x80u;
constexpr uint32_t kOffBcdMon  = 0x84u;
constexpr uint32_t kOffBcdYear = 0x88u;

constexpr uint32_t kRtcConRtcEn   = 1u << 0;
constexpr uint32_t kRtcConClkSel  = 1u << 1;
constexpr uint32_t kRtcConCntSel  = 1u << 2;
constexpr uint32_t kRtcConClkRst  = 1u << 3;
constexpr uint32_t kRtcRstSrstEn  = 1u << 3;
constexpr uint32_t kTicntEnable   = 1u << 7;
constexpr uint32_t kTicntCount    = 0x7Fu;
constexpr int      kIrqTick       = 8;
constexpr int      kIrqRtc        = 30;
constexpr uint64_t kTickHz        = 128ull;
/* S3C2410A UM p.17-1: "The RTC unit works with an external 32.768 kHz crystal"; p.17-3:
   tick "Period = ( n+1 ) / 128 second". */
constexpr uint64_t kRtcxHz        = 32768ull;
constexpr uint64_t kRtcxPerTick   = kRtcxHz / kTickHz;
static_assert(kRtcxHz % kTickHz == 0u, "the 128 Hz tick divides the RTC crystal");

using Cal = S3C2410RtcCalendar;

class S3C2410Rtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }

    void OnReady() override {
        osc_.Attach(kRtcxHz, 1u);
        const OscillatorTicks::Reading now = osc_.Sample();
        total_seen_ = now.total;
        park_seen_  = now.park;
        cal_.SeedFromHost();
        GuestCycleClock& clk = emu_.Get<GuestCycleClock>();
        tick_ev_  = clk.Add([this] { OnTick(); });
        alarm_ev_ = clk.Add([this] { OnAlarmCompare(); });
        clk.RegisterRateListener([this] { OnRateChange(); });
        /* S3C2410A UM p.7-14: "The wakeup from Power_OFF mode can be issued by
           the EINT[15:0] or by RTC alarm interrupt." */
        emu_.Get<GuestDeepSleep>().RegisterParkClock([this] { Advance(); });
        emu_.Get<GuestDeepSleep>().RegisterParkWakeSource([this] { return park_hit_; });
        emu_.Get<GuestDeepSleep>().RegisterParkWakeDue([this] { return AlarmWakeDueNs(); });
        /* S3C2410A UM p.17-3: "When the system is off ... the backup battery only drives the
           oscillation circuit and the BCD counters". */
        emu_.Get<GuestDeepSleep>().RegisterSleepEntryListener([this] {
            Advance();
            if (tick_armed_) {
                emu_.Get<Fatal>().Die("S3C2410Rtc: Power_OFF entered with the tick enabled "
                                      "(TICNT 0x%X); whether the tick counts in Power_OFF is "
                                      "not modelled", ticnt_);
            }
            ReportPark();
            tick_pending_  = false;
            alarm_pending_ = false;
            SyncTickEvent();
            SyncAlarmEvent();
        });
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            OnResetLine();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x57000000u; }
    uint32_t MmioSize() const override { return 0x00000100u; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    uint64_t CreditTicks(uint64_t ticks) {
        frac_ticks_ += ticks;
        const uint64_t secs = frac_ticks_ / kRtcxHz;
        frac_ticks_ %= kRtcxHz;
        if (secs != 0u) cal_.AdvanceSeconds(secs);
        return secs;
    }

    /* S3C2410A UM p.7-15: "For alarm wake-up, check the RTC time because the
       RTC bit of SRCPND isn't set at the alarm wake-up." */
    void Advance() {
        const OscillatorTicks::Reading now = osc_.Sample();
        const uint64_t slept = now.park - park_seen_;
        const uint64_t awake = now.total - total_seen_ - slept;
        total_seen_ = now.total;
        park_seen_  = now.park;
        CreditTicks(awake);
        if (slept != 0u) {
            const Cal was = cal_;
            if (park_ticks_ == 0u) park_from_ = was;
            park_ticks_ += slept;
            const uint64_t secs = CreditTicks(slept);
            park_hit_ = park_hit_ || (alarm_armed_ && alarm_.Crossed(was, secs));
        }
        if (!emu_.Get<GuestEngine>().DeepSleep()) ReportPark();
        if (slept == 0u) return;
        if (alarm_armed_ && alarm_target_ <= total_seen_) ArmNextAlarm();
        else                                              SyncAlarmEvent();
        SyncTickEvent();
    }

    int64_t AlarmWakeDueNs() {
        Advance();
        if (!alarm_armed_ || !alarm_.Enabled()) return GuestDeepSleep::kNoParkWake;
        const uint64_t secs = alarm_.SecondsTo(cal_);
        if (secs == 0u) return GuestDeepSleep::kNoParkWake;
        return osc_.SleptNsAtTick(total_seen_ + secs * kRtcxHz - frac_ticks_);
    }

    void ReportPark() {
        if (park_ticks_ == 0u) return;
        LOG(SocTimer, "[RTCSLEEP] s3c2410 park %llu ms: %02u:%02u:%02u -> %02u:%02u:%02u "
                      "tick=%d alarm=%d hit=%d rtccon=0x%X ticnt=0x%X rtcalm=0x%X\n",
            static_cast<unsigned long long>(ScaleU64(park_ticks_, 1000u, kRtcxHz)),
            park_from_.hour, park_from_.min, park_from_.sec, cal_.hour, cal_.min, cal_.sec,
            static_cast<int>(tick_armed_), static_cast<int>(alarm_armed_),
            static_cast<int>(park_hit_), rtccon_, ticnt_, alarm_.rtcalm);
        park_ticks_ = 0u;
        park_hit_   = false;
    }

    void OnRateChange() {
        Advance();
        osc_.Rescale();
        SyncTickEvent();
        SyncAlarmEvent();
    }

    void OnResetLine() {
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
        rtccon_ = 0;
        ticnt_  = 0;
        rtcrst_ = 0;
        alarm_.Reset();
        tick_armed_    = false;
        alarm_armed_   = false;
        tick_pending_  = false;
        alarm_pending_ = false;
        SyncTickEvent();
        SyncAlarmEvent();
    }

    void ArmAt(GuestCycleClock::Event* ev, uint64_t target) {
        osc_.ArmAt(ev, target);
    }

    uint64_t TickPeriodTicks() const {
        return ((ticnt_ & kTicntCount) + 1u) * kRtcxPerTick;
    }

    void RearmTick() {
        Advance();
        tick_pending_ = tick_pending_ || (tick_armed_ && tick_target_ <= total_seen_);
        tick_armed_   = (ticnt_ & kTicntEnable) != 0u;
        if (tick_armed_) {
            if ((ticnt_ & kTicntCount) == 0u) {
                emu_.Get<Fatal>().Die(
                    "S3C2410Rtc: TICNT enables the tick with count 0, outside the "
                    "documented 1..127 range, which CERF does not model");
            }
            /* S3C2410A UM p.17-2 Figure 17-1: the Time Tick Generator counts the 128 Hz
               output of the 2^15 divider whose 1 Hz output feeds SEC. */
            tick_target_ = total_seen_ + TickPeriodTicks() - frac_ticks_ % kRtcxPerTick;
        }
        SyncTickEvent();
    }

    void SyncEvent(GuestCycleClock::Event* ev, bool armed, uint64_t target) {
        if (armed) {
            ArmAt(ev, target);
            return;
        }
        emu_.Get<GuestCycleClock>().Disarm(ev);
    }

    void SyncTickEvent() {
        if (tick_pending_) {
            ArmAt(tick_ev_, total_seen_);
            return;
        }
        SyncEvent(tick_ev_, tick_armed_, tick_target_);
    }

    void SyncAlarmEvent() {
        if (alarm_pending_) {
            ArmAt(alarm_ev_, total_seen_);
            return;
        }
        SyncEvent(alarm_ev_, alarm_armed_, alarm_target_);
    }

    void OnTick() {
        if (tick_pending_) {
            tick_pending_ = false;
            emu_.Get<IrqController>().AssertIrq(kIrqTick);
            SyncTickEvent();
            return;
        }
        if ((ticnt_ & kTicntEnable) == 0u) {
            tick_armed_ = false;
            return;
        }
        emu_.Get<IrqController>().AssertIrq(kIrqTick);
        tick_target_ += TickPeriodTicks();
        ArmAt(tick_ev_, tick_target_);
    }

    void RearmAlarm() {
        Advance();
        alarm_pending_ = alarm_pending_ || (alarm_armed_ && alarm_target_ <= total_seen_);
        ArmNextAlarm();
    }

    void ArmNextAlarm() {
        const uint64_t secs = alarm_.Enabled() ? alarm_.SecondsTo(cal_) : 0u;
        alarm_armed_ = secs != 0u;
        if (alarm_armed_) alarm_target_ = total_seen_ + secs * kRtcxHz - frac_ticks_;
        SyncAlarmEvent();
    }

    void OnAlarmCompare() {
        Advance();
        if (alarm_pending_ || (alarm_.Enabled() && alarm_.Matches(cal_))) {
            emu_.Get<IrqController>().AssertIrq(kIrqRtc);
        }
        alarm_pending_ = false;
        ArmNextAlarm();
    }

    void SetField(uint32_t off, uint32_t value);

    OscillatorTicks osc_{emu_, true};
    uint64_t total_seen_   = 0;
    uint64_t park_seen_    = 0;
    uint64_t park_ticks_   = 0;
    uint64_t frac_ticks_   = 0;
    uint64_t tick_target_  = 0;
    uint64_t alarm_target_ = 0;
    bool     park_hit_     = false;
    Cal      park_from_;
    Cal      cal_;

    uint32_t        rtccon_ = 0, ticnt_ = 0;
    uint32_t        rtcrst_ = 0;
    S3C2410RtcAlarm alarm_;

    GuestCycleClock::Event* tick_ev_  = nullptr;
    GuestCycleClock::Event* alarm_ev_ = nullptr;
    bool     tick_armed_      = false;
    bool     alarm_armed_     = false;
    bool     tick_pending_    = false;
    bool     alarm_pending_   = false;
};

uint32_t S3C2410Rtc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    switch (off) {
        case kOffRtcCon:  return rtccon_;
        case kOffTicnt:   return ticnt_;
        case kOffRtcAlm:  return alarm_.rtcalm;
        case kOffAlmSec:  return alarm_.sec;
        case kOffAlmMin:  return alarm_.min;
        case kOffAlmHour: return alarm_.hour;
        case kOffAlmDate: return alarm_.date;
        case kOffAlmMon:  return alarm_.mon;
        case kOffAlmYear: return alarm_.year;
        case kOffRtcRst:  return rtcrst_;
        default: break;
    }

    Advance();
    switch (off) {
        case kOffBcdSec:  return Cal::ToBcd(cal_.sec);
        case kOffBcdMin:  return Cal::ToBcd(cal_.min);
        case kOffBcdHour: return Cal::ToBcd(cal_.hour);
        case kOffBcdDate: return Cal::ToBcd(cal_.date);
        case kOffBcdDay:  return cal_.day;
        case kOffBcdMon:  return Cal::ToBcd(cal_.mon);
        case kOffBcdYear: return Cal::ToBcd(cal_.year);
        default:
            HaltUnsupportedAccess("ReadWord", addr, 0);
    }
}

void S3C2410Rtc::SetField(uint32_t off, uint32_t value) {
    Advance();
    const Cal::Field* field  = nullptr;
    uint32_t*         target = nullptr;
    switch (off) {
        case kOffBcdSec:  field = &Cal::kSec;  target = &cal_.sec;  break;
        case kOffBcdMin:  field = &Cal::kMin;  target = &cal_.min;  break;
        case kOffBcdHour: field = &Cal::kHour; target = &cal_.hour; break;
        case kOffBcdDate: field = &Cal::kDate; target = &cal_.date; break;
        case kOffBcdMon:  field = &Cal::kMon;  target = &cal_.mon;  break;
        case kOffBcdYear: field = &Cal::kYear; target = &cal_.year; break;
        case kOffBcdDay:  field = &Cal::kDay;  target = &cal_.day;  break;
        default:
            emu_.Get<Fatal>().Die(
                "S3C2410Rtc: SetField reached offset +0x%02X, which is not a BCD "
                "counter", off);
    }
    const uint32_t decoded = off == kOffBcdDay ? (value & field->mask)
                                               : Cal::FromBcd(value & field->mask);
    if (!Cal::Holds(*field, decoded)) {
        emu_.Get<Fatal>().Die(
            "S3C2410Rtc: the guest wrote 0x%02X to the BCD register at +0x%02X, "
            "outside its documented range, which CERF does not model", value, off);
    }
    *target = decoded;
}

void S3C2410Rtc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    switch (off) {
        /* S3C2410A UM p.17-5: RTCCON CLKRST [3] resets the RTC clock count,
           CNTSEL [2] separates the BCD counters, CLKSEL [1] selects the test
           clock; only RTCEN [0] gates the BCD registers. */
        case kOffRtcCon: {
            const uint32_t unmodelled =
                value & (kRtcConClkRst | kRtcConCntSel | kRtcConClkSel);
            if (unmodelled != 0u) {
                emu_.Get<Fatal>().Die(
                    "S3C2410Rtc: RTCCON sets 0x%X, whose effect CERF does not "
                    "model", unmodelled);
            }
            rtccon_ = value;
            return;
        }
        case kOffTicnt:   ticnt_  = value; RearmTick();  return;
        case kOffRtcAlm:  alarm_.rtcalm = value; RearmAlarm(); return;
        case kOffAlmSec:  alarm_.sec    = value; RearmAlarm(); return;
        case kOffAlmMin:  alarm_.min    = value; RearmAlarm(); return;
        case kOffAlmHour: alarm_.hour   = value; RearmAlarm(); return;
        case kOffAlmDate: alarm_.date   = value; RearmAlarm(); return;
        case kOffAlmMon:  alarm_.mon    = value; RearmAlarm(); return;
        case kOffAlmYear: alarm_.year   = value; RearmAlarm(); return;
        /* S3C2410A UM p.17-9: RTCRST SRSTEN [3] enables the round second reset
           at the SECCR [2:0] carry boundary. */
        case kOffRtcRst:
            if ((value & kRtcRstSrstEn) != 0u) {
                emu_.Get<Fatal>().Die(
                    "S3C2410Rtc: RTCRST enables the round second reset, which "
                    "CERF does not model");
            }
            rtcrst_ = value;
            return;
        case kOffBcdSec: case kOffBcdMin: case kOffBcdHour: case kOffBcdDate:
        case kOffBcdDay: case kOffBcdMon: case kOffBcdYear:
            /* S3C2410A UM p.17-3: bit 0 of RTCCON must be set high in order to
               write the BCD register in the RTC block. */
            if ((rtccon_ & kRtcConRtcEn) != 0u) {
                SetField(off, value);
                RearmAlarm();
            }
            return;
        default:
            HaltUnsupportedAccess("WriteWord", addr, value);
    }
}

void S3C2410Rtc::SaveState(StateWriter& w) {
    Advance();
    osc_.Save(w);
    w.Write("frac_ticks", frac_ticks_);
    w.Write("sec", cal_.sec);   w.Write("min", cal_.min);  w.Write("hour", cal_.hour);
    w.Write("date", cal_.date);  w.Write("day", cal_.day);  w.Write("mon", cal_.mon);
    w.Write("year", cal_.year);
    w.Write("rtccon", rtccon_);  w.Write("ticnt", ticnt_);   w.Write("rtcalm", alarm_.rtcalm);
    w.Write("almsec", alarm_.sec);  w.Write("almmin", alarm_.min);  w.Write("almhour", alarm_.hour);
    w.Write("almdate", alarm_.date); w.Write("almmon", alarm_.mon);  w.Write("almyear", alarm_.year);
    w.Write("rtcrst", rtcrst_);
    w.Write("tick_target", tick_target_);  w.Write("alarm_target", alarm_target_);
    w.Write<uint8_t>("tick_armed", tick_armed_ ? 1u : 0u);
    w.Write<uint8_t>("alarm_armed", alarm_armed_ ? 1u : 0u);
    w.Write<uint8_t>("tick_pending", tick_pending_ ? 1u : 0u);
    w.Write<uint8_t>("alarm_pending", alarm_pending_ ? 1u : 0u);
}

void S3C2410Rtc::RestoreState(StateReader& r) {
    osc_.Restore(r);
    r.Read("frac_ticks", frac_ticks_);
    if (frac_ticks_ >= kRtcxHz) {
        r.Reject("S3C2410Rtc: restored sub-second tick %llu of a %llu Hz crystal",
                 static_cast<unsigned long long>(frac_ticks_),
                 static_cast<unsigned long long>(kRtcxHz));
    }
    r.Read("sec", cal_.sec);   r.Read("min", cal_.min);  r.Read("hour", cal_.hour);
    r.Read("date", cal_.date);  r.Read("day", cal_.day);  r.Read("mon", cal_.mon);
    r.Read("year", cal_.year);
    if (!cal_.Valid()) {
        r.Reject("S3C2410Rtc: restored calendar %u-%u-%u %u:%u:%u day %u is out of range",
                 cal_.year, cal_.mon, cal_.date, cal_.hour, cal_.min, cal_.sec, cal_.day);
    }
    r.Read("rtccon", rtccon_);  r.Read("ticnt", ticnt_);   r.Read("rtcalm", alarm_.rtcalm);
    r.Read("almsec", alarm_.sec);  r.Read("almmin", alarm_.min);  r.Read("almhour", alarm_.hour);
    r.Read("almdate", alarm_.date); r.Read("almmon", alarm_.mon);  r.Read("almyear", alarm_.year);
    r.Read("rtcrst", rtcrst_);
    if ((rtccon_ & (kRtcConClkRst | kRtcConCntSel | kRtcConClkSel)) != 0u ||
        (rtcrst_ & kRtcRstSrstEn) != 0u ||
        ((ticnt_ & kTicntEnable) != 0u && (ticnt_ & kTicntCount) == 0u)) {
        r.Reject("S3C2410Rtc: restored RTCCON 0x%X, RTCRST 0x%X or TICNT 0x%X sets a mode "
                 "CERF does not model", rtccon_, rtcrst_, ticnt_);
    }
    r.Read("tick_target", tick_target_);  r.Read("alarm_target", alarm_target_);
    uint8_t ta = 0, aa = 0, tp = 0, ap = 0;
    r.Read("tick_armed", ta);  r.Read("alarm_armed", aa);
    r.Read("tick_pending", tp);  r.Read("alarm_pending", ap);
    if (ta > 1u || aa > 1u || tp > 1u || ap > 1u) {
        r.Reject("S3C2410Rtc: an armed or pending flag above 1");
    }
    if ((ta != 0u) != ((ticnt_ & kTicntEnable) != 0u)) {
        r.Reject("S3C2410Rtc: restored tick armed flag %u with TICNT 0x%X", ta, ticnt_);
    }
    tick_armed_    = ta != 0u;
    alarm_armed_   = aa != 0u;
    tick_pending_  = tp != 0u;
    alarm_pending_ = ap != 0u;
    const OscillatorTicks::Reading now = osc_.Sample();
    total_seen_    = now.total;
    park_seen_     = now.park;
    park_ticks_    = 0u;
    park_hit_      = false;
    SyncTickEvent();
    SyncAlarmEvent();
}

}

REGISTER_SERVICE(S3C2410Rtc);
