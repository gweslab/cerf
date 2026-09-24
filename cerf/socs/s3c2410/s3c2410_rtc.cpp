#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/tick_scale.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"
#include "s3c2410_clocks.h"

#include <cstdint>
#include <ctime>

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
constexpr uint32_t kRtcAlmEn      = 1u << 6;
constexpr uint32_t kRtcAlmYear    = 1u << 5;
constexpr uint32_t kRtcAlmMon     = 1u << 4;
constexpr uint32_t kRtcAlmDate    = 1u << 3;
constexpr uint32_t kRtcAlmHour    = 1u << 2;
constexpr uint32_t kRtcAlmMin     = 1u << 1;
constexpr uint32_t kRtcAlmSec     = 1u << 0;
constexpr int      kIrqTick       = 8;
constexpr int      kIrqRtc        = 30;
constexpr uint64_t kTickHz        = 128ull;
constexpr uint64_t kNsPerSec      = 1000000000ull;

class S3C2410Rtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }

    void OnReady() override {
        rate_hz_ = emu_.Get<S3C2410Clocks>().CoreClockHz();
        if (rate_hz_ == 0u) {
            emu_.Get<Fatal>().Die("S3C2410Rtc: the SoC reports a 0 Hz core clock");
        }
        origin_cycles_ = emu_.Get<GuestCycleClock>().Cycles();
        SeedFromHost();
        GuestCycleClock& clk = emu_.Get<GuestCycleClock>();
        tick_ev_  = clk.Add([this] { OnTick(); });
        alarm_ev_ = clk.Add([this] { OnAlarmCompare(); });
        emu_.Get<S3C2410Clocks>().RegisterRateListener([this] { OnRateChange(); });
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
    void PostRestore() override;

private:
    static uint32_t ToBcd(uint32_t v) { return ((v / 10u) << 4) | (v % 10u); }
    static uint32_t FromBcd(uint32_t v) { return ((v >> 4) & 0xFu) * 10u + (v & 0xFu); }

    /* S3C2410A UM p.17-1: "Leap year generator" and "Year 2000 problem is
       removed"; p.17-8 gives the alarm date range "from 0 to 28, 29, 30, 31". */
    static uint32_t DaysInMonth(uint32_t mon, uint32_t year) {
        static const uint32_t kLen[12] = {31u, 28u, 31u, 30u, 31u, 30u,
                                          31u, 31u, 30u, 31u, 30u, 31u};
        if (mon == 2u && (year % 4u) == 0u) return 29u;
        return kLen[mon - 1u];
    }

    void SeedFromHost() {
        const std::time_t t = std::time(nullptr);
        std::tm           lt{};
        localtime_s(&lt, &t);
        sec_  = static_cast<uint32_t>(lt.tm_sec % 60);
        min_  = static_cast<uint32_t>(lt.tm_min);
        hour_ = static_cast<uint32_t>(lt.tm_hour);
        date_ = static_cast<uint32_t>(lt.tm_mday);
        mon_  = static_cast<uint32_t>(lt.tm_mon + 1);
        year_ = static_cast<uint32_t>((lt.tm_year + 1900) % 100);
        day_  = static_cast<uint32_t>(lt.tm_wday + 1);
    }

    void AdvanceOneDay() {
        day_ = day_ % 7u + 1u;
        if (date_ < DaysInMonth(mon_, year_)) {
            ++date_;
            return;
        }
        date_ = 1u;
        if (mon_ < 12u) {
            ++mon_;
            return;
        }
        mon_  = 1u;
        year_ = (year_ + 1u) % 100u;
    }

    void AdvanceSeconds(uint64_t secs) {
        uint64_t t = sec_ + secs;
        sec_ = static_cast<uint32_t>(t % 60u);
        t    = min_ + t / 60u;
        min_ = static_cast<uint32_t>(t % 60u);
        t    = hour_ + t / 60u;
        hour_ = static_cast<uint32_t>(t % 24u);
        for (uint64_t days = t / 24u; days > 0u; --days) AdvanceOneDay();
    }

    void Advance() {
        const uint64_t now   = emu_.Get<GuestCycleClock>().Cycles();
        const uint64_t delta = now - origin_cycles_;
        const uint64_t whole = (delta / rate_hz_) * kNsPerSec;
        const uint64_t part  = (delta % rate_hz_) * kNsPerSec + ns_rem_;
        ns_rem_ = part % rate_hz_;
        const uint64_t d = whole + part / rate_hz_;
        origin_cycles_ = now;
        mono_ns_ += static_cast<int64_t>(d);
        frac_ns_ += d;
        const uint64_t secs = frac_ns_ / kNsPerSec;
        frac_ns_ %= kNsPerSec;
        if (secs != 0u) AdvanceSeconds(secs);
    }

    void OnRateChange() {
        Advance();
        const uint64_t hz = emu_.Get<S3C2410Clocks>().CoreClockHz();
        if (hz == 0u) {
            emu_.Get<Fatal>().Die("S3C2410Rtc: the SoC reports a 0 Hz core clock");
        }
        rate_hz_ = hz;
        ns_rem_  = 0;
        if (tick_armed_)  ArmAt(tick_ev_, tick_target_ns_);
        if (alarm_armed_) ArmAt(alarm_ev_, alarm_target_ns_);
    }

    void OnResetLine() {
        rtccon_  = 0;
        ticnt_   = 0;
        rtcalm_  = 0;
        almsec_  = 0;
        almmin_  = 0;
        almhour_ = 0;
        almdate_ = 0x01u;
        almmon_  = 0x01u;
        almyear_ = 0;
        rtcrst_  = 0;
        if (tick_armed_)  emu_.Get<GuestCycleClock>().Disarm(tick_ev_);
        if (alarm_armed_) emu_.Get<GuestCycleClock>().Disarm(alarm_ev_);
        tick_armed_  = false;
        alarm_armed_ = false;
    }

    void ArmAt(GuestCycleClock::Event* ev, int64_t target_ns) {
        Advance();
        const int64_t  delta = target_ns > mono_ns_ ? target_ns - mono_ns_ : 0;
        const uint64_t cyc   = ScaleU64(static_cast<uint64_t>(delta), rate_hz_, kNsPerSec);
        emu_.Get<GuestCycleClock>().Arm(ev, origin_cycles_ + cyc);
    }

    int64_t TickPeriodNs() const {
        const uint64_t n = (ticnt_ & kTicntCount) + 1u;
        return static_cast<int64_t>(ScaleU64(n, kNsPerSec, kTickHz));
    }

    void RearmTick() {
        if ((ticnt_ & kTicntEnable) == 0u) {
            if (tick_armed_) emu_.Get<GuestCycleClock>().Disarm(tick_ev_);
            tick_armed_ = false;
            return;
        }
        if ((ticnt_ & kTicntCount) == 0u) {
            emu_.Get<Fatal>().Die(
                "S3C2410Rtc: TICNT enables the tick with count 0, outside the "
                "documented 1..127 range, which CERF does not model");
        }
        Advance();
        tick_target_ns_ = mono_ns_ + TickPeriodNs();
        tick_armed_     = true;
        ArmAt(tick_ev_, tick_target_ns_);
    }

    void SyncEvent(GuestCycleClock::Event* ev, bool armed, int64_t target_ns) {
        if (armed) {
            ArmAt(ev, target_ns);
            return;
        }
        emu_.Get<GuestCycleClock>().Disarm(ev);
    }

    void OnTick() {
        if ((ticnt_ & kTicntEnable) == 0u) {
            tick_armed_ = false;
            return;
        }
        emu_.Get<IrqController>().AssertIrq(kIrqTick);
        tick_target_ns_ += TickPeriodNs();
        ArmAt(tick_ev_, tick_target_ns_);
    }

    void RearmAlarm() {
        if ((rtcalm_ & kRtcAlmEn) == 0u) {
            if (alarm_armed_) emu_.Get<GuestCycleClock>().Disarm(alarm_ev_);
            alarm_armed_ = false;
            return;
        }
        Advance();
        alarm_target_ns_ = mono_ns_ - (mono_ns_ % static_cast<int64_t>(kNsPerSec)) +
                           static_cast<int64_t>(kNsPerSec);
        alarm_armed_     = true;
        ArmAt(alarm_ev_, alarm_target_ns_);
    }

    void OnAlarmCompare() {
        if ((rtcalm_ & kRtcAlmEn) == 0u) {
            alarm_armed_ = false;
            return;
        }
        Advance();
        bool match = true;
        if ((rtcalm_ & kRtcAlmSec)  != 0u && ToBcd(sec_)  != (almsec_  & 0x7Fu)) match = false;
        if ((rtcalm_ & kRtcAlmMin)  != 0u && ToBcd(min_)  != (almmin_  & 0x7Fu)) match = false;
        if ((rtcalm_ & kRtcAlmHour) != 0u && ToBcd(hour_) != (almhour_ & 0x3Fu)) match = false;
        if ((rtcalm_ & kRtcAlmDate) != 0u && ToBcd(date_) != (almdate_ & 0x3Fu)) match = false;
        if ((rtcalm_ & kRtcAlmMon)  != 0u && ToBcd(mon_)  != (almmon_  & 0x1Fu)) match = false;
        if ((rtcalm_ & kRtcAlmYear) != 0u && ToBcd(year_) != (almyear_ & 0xFFu)) match = false;
        if (match) emu_.Get<IrqController>().AssertIrq(kIrqRtc);
        alarm_target_ns_ += static_cast<int64_t>(kNsPerSec);
        ArmAt(alarm_ev_, alarm_target_ns_);
    }

    void SetField(uint32_t off, uint32_t value);

    uint64_t origin_cycles_ = 0;
    uint64_t rate_hz_       = 0;
    uint64_t ns_rem_        = 0;
    uint64_t frac_ns_       = 0;
    int64_t  mono_ns_       = 0;

    uint32_t sec_ = 0, min_ = 0, hour_ = 0;
    uint32_t date_ = 1, day_ = 1, mon_ = 1, year_ = 0;

    uint32_t rtccon_ = 0, ticnt_ = 0;
    uint32_t rtcalm_ = 0;
    uint32_t almsec_ = 0, almmin_ = 0, almhour_ = 0;
    uint32_t almdate_ = 0x01u, almmon_ = 0x01u, almyear_ = 0;
    uint32_t rtcrst_ = 0;

    GuestCycleClock::Event* tick_ev_  = nullptr;
    GuestCycleClock::Event* alarm_ev_ = nullptr;
    int64_t  tick_target_ns_  = 0;
    int64_t  alarm_target_ns_ = 0;
    bool     tick_armed_      = false;
    bool     alarm_armed_     = false;
};

uint32_t S3C2410Rtc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    switch (off) {
        case kOffRtcCon:  return rtccon_;
        case kOffTicnt:   return ticnt_;
        case kOffRtcAlm:  return rtcalm_;
        case kOffAlmSec:  return almsec_;
        case kOffAlmMin:  return almmin_;
        case kOffAlmHour: return almhour_;
        case kOffAlmDate: return almdate_;
        case kOffAlmMon:  return almmon_;
        case kOffAlmYear: return almyear_;
        case kOffRtcRst:  return rtcrst_;
        default: break;
    }

    Advance();
    switch (off) {
        case kOffBcdSec:  return ToBcd(sec_);
        case kOffBcdMin:  return ToBcd(min_);
        case kOffBcdHour: return ToBcd(hour_);
        case kOffBcdDate: return ToBcd(date_);
        case kOffBcdDay:  return day_;
        case kOffBcdMon:  return ToBcd(mon_);
        case kOffBcdYear: return ToBcd(year_);
        default:
            HaltUnsupportedAccess("ReadWord", addr, 0);
    }
}

void S3C2410Rtc::SetField(uint32_t off, uint32_t value) {
    Advance();
    uint32_t  decoded = 0;
    uint32_t  lo      = 0;
    uint32_t  hi      = 0;
    uint32_t* target  = nullptr;
    switch (off) {
        case kOffBcdSec:  decoded = FromBcd(value & 0x7Fu); lo = 0;  hi = 59; target = &sec_;  break;
        case kOffBcdMin:  decoded = FromBcd(value & 0x7Fu); lo = 0;  hi = 59; target = &min_;  break;
        case kOffBcdHour: decoded = FromBcd(value & 0x3Fu); lo = 0;  hi = 23; target = &hour_; break;
        case kOffBcdDate: decoded = FromBcd(value & 0x3Fu); lo = 1;  hi = 31; target = &date_; break;
        case kOffBcdMon:  decoded = FromBcd(value & 0x1Fu); lo = 1;  hi = 12; target = &mon_;  break;
        case kOffBcdYear: decoded = FromBcd(value & 0xFFu); lo = 0;  hi = 99; target = &year_; break;
        case kOffBcdDay:  decoded = value & 0x7u;           lo = 1;  hi = 7;  target = &day_;  break;
        default:
            emu_.Get<Fatal>().Die(
                "S3C2410Rtc: SetField reached offset +0x%02X, which is not a BCD "
                "counter", off);
    }
    if (decoded < lo || decoded > hi) {
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
        case kOffRtcAlm:  rtcalm_ = value; RearmAlarm(); return;
        case kOffAlmSec:  almsec_  = value; return;
        case kOffAlmMin:  almmin_  = value; return;
        case kOffAlmHour: almhour_ = value; return;
        case kOffAlmDate: almdate_ = value; return;
        case kOffAlmMon:  almmon_  = value; return;
        case kOffAlmYear: almyear_ = value; return;
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
            if ((rtccon_ & kRtcConRtcEn) != 0u) SetField(off, value);
            return;
        default:
            HaltUnsupportedAccess("WriteWord", addr, value);
    }
}

void S3C2410Rtc::SaveState(StateWriter& w) {
    Advance();
    w.Write("mono_ns", mono_ns_);  w.Write("ns_rem", ns_rem_);  w.Write("frac_ns", frac_ns_);
    w.Write("sec", sec_);   w.Write("min", min_);  w.Write("hour", hour_);
    w.Write("date", date_);  w.Write("day", day_);  w.Write("mon", mon_);   w.Write("year", year_);
    w.Write("rtccon", rtccon_);  w.Write("ticnt", ticnt_);   w.Write("rtcalm", rtcalm_);
    w.Write("almsec", almsec_);  w.Write("almmin", almmin_);  w.Write("almhour", almhour_);
    w.Write("almdate", almdate_); w.Write("almmon", almmon_);  w.Write("almyear", almyear_);
    w.Write("rtcrst", rtcrst_);
    w.Write("tick_target_ns", tick_target_ns_);  w.Write("alarm_target_ns", alarm_target_ns_);
    w.Write<uint8_t>("tick_armed", tick_armed_ ? 1u : 0u);
    w.Write<uint8_t>("alarm_armed", alarm_armed_ ? 1u : 0u);
}

void S3C2410Rtc::RestoreState(StateReader& r) {
    r.Read("mono_ns", mono_ns_);  r.Read("ns_rem", ns_rem_);  r.Read("frac_ns", frac_ns_);
    r.Read("sec", sec_);   r.Read("min", min_);  r.Read("hour", hour_);
    r.Read("date", date_);  r.Read("day", day_);  r.Read("mon", mon_);   r.Read("year", year_);
    r.Read("rtccon", rtccon_);  r.Read("ticnt", ticnt_);   r.Read("rtcalm", rtcalm_);
    r.Read("almsec", almsec_);  r.Read("almmin", almmin_);  r.Read("almhour", almhour_);
    r.Read("almdate", almdate_); r.Read("almmon", almmon_);  r.Read("almyear", almyear_);
    r.Read("rtcrst", rtcrst_);
    r.Read("tick_target_ns", tick_target_ns_);  r.Read("alarm_target_ns", alarm_target_ns_);
    uint8_t ta = 0, aa = 0;
    r.Read("tick_armed", ta);  r.Read("alarm_armed", aa);
    tick_armed_  = ta != 0u;
    alarm_armed_ = aa != 0u;
}

void S3C2410Rtc::PostRestore() {
    origin_cycles_ = emu_.Get<GuestCycleClock>().Cycles();
    rate_hz_       = emu_.Get<S3C2410Clocks>().CoreClockHz();
    if (rate_hz_ == 0u) {
        emu_.Get<Fatal>().Die("S3C2410Rtc: the SoC reports a 0 Hz core clock");
    }
    SyncEvent(tick_ev_, tick_armed_, tick_target_ns_);
    SyncEvent(alarm_ev_, alarm_armed_, alarm_target_ns_);
}

}

REGISTER_SERVICE(S3C2410Rtc);
