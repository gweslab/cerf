#include "vr41xx_rtc.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../host/guest_deep_sleep.h"
#include "../../jit/mips/mips_core_clock.h"
#include "../../jit/mips/mips_interrupt_channel.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "vr41xx_icu.h"
#include "vr41xx_pmu.h"

#include <algorithm>
#include <cstdint>

namespace {

/* RTC1 block offsets from 0x0B0000C0 (UM Table 16-1 == Table 17-1). */
enum : uint32_t {
    kEtimeL = 0x00, kEtimeM = 0x02, kEtimeH = 0x04,
    kEcmpL  = 0x08, kEcmpM  = 0x0A, kEcmpH  = 0x0C,
    kRtcl1L = 0x10, kRtcl1H = 0x12, kRtcl1CntL = 0x14, kRtcl1CntH = 0x16,
    kRtcl2L = 0x18, kRtcl2H = 0x1A, kRtcl2CntL = 0x1C, kRtcl2CntH = 0x1E,
};
/* RTC2 block offsets from 0x0B0001C0 (UM Table 16-1 == Table 17-1). */
enum : uint32_t {
    kTclkL = 0x00, kTclkH = 0x02, kTclkCntL = 0x04, kTclkCntH = 0x06,
    kRtcIntReg = 0x1E,
};

constexpr uint16_t kRtcIntMask = 0x000Fu;   /* RTCINTREG D3:0 (UM 16.2.9 p353 == 17.2.9 p437) */

constexpr uint64_t kNever = UINT64_MAX;

}  /* namespace */

void Vr41xxRtc::OnReady() {
    clock_      = &emu_.Get<GuestCycleClock>();
    core_clock_ = &emu_.Get<MipsCoreClock>();
    channel_    = &emu_.Get<MipsInterruptChannel>();
    event_      = clock_->Add([this] {
        std::lock_guard<std::mutex> lk(mtx_);
        UpdateLocked();
    });
    rtcx_.Attach();
    tclk_anchor_cycle_ = TclkCyclesLocked();
    clock_->RegisterRateListener([this] { OnRateChange(); });
    channel_->RegisterSuspendListener([this] {
        std::lock_guard<std::mutex> lk(mtx_);
        UpdateLocked();
    });

    emu_.Get<PeripheralDispatcher>().Register(this);

    /* "When the RTCRST# signal is asserted, the PMU resets all peripheral units including
       the RTC unit"; an RSTSW reset leaves the RTC "Active" (UM 15.1.1, Table 15-1). On a
       non-RTCRST reset ETIME "Continues counting" (UM 16.2.1) and ECMP / RTCLong1 / RTCLong2
       hold their values (UM 16.2.2-16.2.6), but the TClock unit takes its Other-resets row:
       TCLKLREG/TCLKHREG and TCLKCNTLREG/TCLKCNTHREG are 0 (UM 16.2.7-16.2.8, p349-352) and
       "The TCLK unit is stopped when all zeros are written" (UM 16.2.7 Caution, p350);
       RTCINTREG clears D3 there while D2:0 are retained (UM 16.2.9, p353). */
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (kind == ResetLineKind::Rtc) ApplyRtcResetLocked();
        else                            StopTclkLocked();
        UpdateLocked();
    });

    /* Hibernate startup factor "an Elapsed Time timer interrupt" (VR4131 UM U15350EJ2V0UM
       12.1.3 p216); PMUINTREG D9 RTCINTR "RTC alarm interrupt detection" (VR4102 UM 15.2.1). */
    emu_.Get<GuestDeepSleep>().RegisterParkClock([this] {
        std::lock_guard<std::mutex> lk(mtx_);
        UpdateLocked();
        if ((rtcintreg_ & kIntElapsed) != 0u) emu_.Get<Vr41xxPmu>().LatchRtcAlarmWake();
    });
    emu_.Get<GuestDeepSleep>().RegisterParkWakeSource([this] {
        std::lock_guard<std::mutex> lk(mtx_);
        return (rtcintreg_ & kIntElapsed) != 0u;
    });
    emu_.Get<GuestDeepSleep>().RegisterParkWakeDue([this] {
        std::lock_guard<std::mutex> lk(mtx_);
        UpdateLocked();
        const uint64_t now = RtcTicksLocked();
        const bool latched = (rtcintreg_ & kIntElapsed) != 0u;
        if (!latched && !ecmp_armed_) return GuestDeepSleep::kNoParkWake;
        const uint64_t match = latched ? now : ecmp_match_;
        const int64_t  due   = rtcx_.SleptNsAtTick(match);
        LOG(SocRtc, "[RTC] park wake due: ECMP match in %llu RTCX ticks%s, at slept %lld ns\n",
            static_cast<unsigned long long>(match - now), latched ? " (already latched)" : "",
            static_cast<long long>(due));
        return due;
    });
}

void Vr41xxRtc::OnRateChange() {
    std::lock_guard<std::mutex> lk(mtx_);
    rtcx_.Rescale();
    UpdateLocked();
}

uint64_t Vr41xxRtc::RtcTicksLocked() {
    return rtcx_.Now();
}

/* "TClockCount ... counts down using TClock cycles" (VR4102 UM 16.1 p335); entering Suspend
   takes "TClock high" (VR4102 UM Figure 15-9 p325, VR4121 UM 8.4.1(3)). */
uint64_t Vr41xxRtc::TclkCyclesLocked() const {
    return channel_->CyclesOutsideSuspend();
}

uint64_t Vr41xxRtc::TclkTicksLocked() const {
    return (TclkCyclesLocked() - tclk_anchor_cycle_) / tclk_cycles_;
}

/* Every RTC register's RTCRST column is 0 (UM 16.2.1-16.2.9). */
void Vr41xxRtc::ApplyRtcResetLocked() {
    const uint64_t now = RtcTicksLocked();
    etime_base_   = 0;
    etime_anchor_ = now;
    ecmp_         = 0;
    ecmp_armed_   = false;
    rtcl1_reload_ = 0; rtcl2_reload_ = 0;
    rtcl1_anchor_ = now; rtcl2_anchor_ = now;
    rtcl1_periods_ack_ = 0; rtcl2_periods_ack_ = 0;
    StopTclkLocked();
    rtcintreg_    = 0;
    etime_latch_.Clear();
    ecmp_latch_.Clear();
    rtcl_latch_[0].Clear();
    rtcl_latch_[1].Clear();
    rephase_.Forget();
}

void Vr41xxRtc::StopTclkLocked() {
    tclk_latch_.Clear();
    tclk_reload_       = 0;
    tclk_anchor_cycle_ = TclkCyclesLocked();
    tclk_periods_ack_  = 0;
    rtcintreg_         = static_cast<uint16_t>(rtcintreg_ & ~kIntTclk);
}

void Vr41xxRtc::StartTclkLocked() {
    tclk_anchor_cycle_ = TclkCyclesLocked();
    tclk_periods_ack_  = 0;
    if (tclk_reload_ != 0u) tclk_cycles_ = core_clock_->CyclesPerTclkCounterTick();
}

void Vr41xxRtc::AckIntBitsLocked(uint16_t clr) {
    rtcintreg_ = static_cast<uint16_t>(rtcintreg_ & ~clr);
    const uint64_t now = RtcTicksLocked();
    if (clr & kIntLong1) rtcl1_periods_ack_ = PeriodsReached(rtcl1_reload_, now - rtcl1_anchor_);
    if (clr & kIntLong2) rtcl2_periods_ack_ = PeriodsReached(rtcl2_reload_, now - rtcl2_anchor_);
    if (clr & kIntTclk)  tclk_periods_ack_  = PeriodsReached(tclk_reload_, TclkTicksLocked());
}

uint64_t Vr41xxRtc::ReadEtimeLocked() {
    return (etime_base_ + (RtcTicksLocked() - etime_anchor_)) & kMask48;
}

uint32_t Vr41xxRtc::DownCount(uint32_t reload, uint64_t elapsed, uint32_t mask) {
    if (reload == 0) return 0;
    return static_cast<uint32_t>(reload - elapsed % reload) & mask;
}

uint64_t Vr41xxRtc::PeriodsReached(uint32_t reload, uint64_t elapsed) {
    if (reload == 0) return 0;
    return (elapsed + 1u) / reload;
}

/* "When a match occurs with the Elapsed Time compare registers, an alarm (Elapsed Time
   interrupt) occurs (and the count-up continues)" (VR4131 UM 13.2.1 p239, VR4121 UM 17.2.1). */
void Vr41xxRtc::ArmEcmpLocked() {
    const uint64_t now = RtcTicksLocked();
    const uint64_t etime = (etime_base_ + (now - etime_anchor_)) & kMask48;
    ecmp_match_ = now + ((ecmp_ - etime) & kMask48);
}

void Vr41xxRtc::EvaluateLocked() {
    const uint64_t now = RtcTicksLocked();
    if (ecmp_armed_ && now >= ecmp_match_) {
        rtcintreg_ |= kIntElapsed;
        ecmp_match_ += kMask48 + 1u;
    }
    if (PeriodsReached(rtcl1_reload_, now - rtcl1_anchor_) > rtcl1_periods_ack_) {
        rtcintreg_ |= kIntLong1;
        rephase_.OnMatch(0);
    }
    if (PeriodsReached(rtcl2_reload_, now - rtcl2_anchor_) > rtcl2_periods_ack_) {
        rtcintreg_ |= kIntLong2;
        rephase_.OnMatch(1);
    }
    if (PeriodsReached(tclk_reload_, TclkTicksLocked()) > tclk_periods_ack_)
        rtcintreg_ |= kIntTclk;
}

void Vr41xxRtc::DriveIcuLocked() {
    auto& icu = emu_.Get<Vr41xxIcu>();
    icu.SetSysint1Source(1u << 3, (rtcintreg_ & kIntElapsed) != 0);   /* ETIMER  */
    icu.SetSysint1Source(1u << 2, (rtcintreg_ & kIntLong1)   != 0);   /* RTCL1   */
    icu.SetSysint2Source(1u << 0, (rtcintreg_ & kIntLong2)   != 0);   /* RTCL2   */
    icu.SetSysint2Source(1u << 3, (rtcintreg_ & kIntTclk)    != 0);   /* TCLK    */
}

void Vr41xxRtc::ArmNextLocked() {
    const uint64_t cycles = clock_->Cycles();
    const auto cycle_of_rtc_tick = [this](uint64_t tick) { return rtcx_.CycleOf(tick); };
    const auto next_boundary = [](uint64_t anchor, uint32_t reload, uint64_t ack) {
        return anchor + (ack + 1u) * reload - 1u;
    };
    uint64_t next = kNever;
    if (ecmp_armed_) next = std::min(next, cycle_of_rtc_tick(ecmp_match_));
    if (rtcl1_reload_ != 0u && (rtcintreg_ & kIntLong1) == 0u)
        next = std::min(next, cycle_of_rtc_tick(
                                  next_boundary(rtcl1_anchor_, rtcl1_reload_, rtcl1_periods_ack_)));
    if (rtcl2_reload_ != 0u && (rtcintreg_ & kIntLong2) == 0u)
        next = std::min(next, cycle_of_rtc_tick(
                                  next_boundary(rtcl2_anchor_, rtcl2_reload_, rtcl2_periods_ack_)));
    if (tclk_reload_ != 0u && (rtcintreg_ & kIntTclk) == 0u && !channel_->Suspended())
        next = std::min(next, tclk_anchor_cycle_ +
                                  next_boundary(0u, tclk_reload_, tclk_periods_ack_) * tclk_cycles_ +
                                  (cycles - TclkCyclesLocked()));
    if (next == kNever) clock_->Disarm(event_);
    else                clock_->Arm(event_, std::max(next, cycles));
}

void Vr41xxRtc::UpdateLocked() {
    EvaluateLocked();
    DriveIcuLocked();
    ArmNextLocked();
    rephase_.Report(clock_->NowNs());
}

Vr41xxRtclView Vr41xxRtc::RtclViewLocked(int ch, uint64_t now) {
    Vr41xxRtclView v;
    v.reload  = ch == 0 ? rtcl1_reload_ : rtcl2_reload_;
    v.anchor  = ch == 0 ? rtcl1_anchor_ : rtcl2_anchor_;
    v.ack     = ch == 0 ? rtcl1_periods_ack_ : rtcl2_periods_ack_;
    v.latched   = (rtcintreg_ & (ch == 0 ? kIntLong1 : kIntLong2)) != 0u;
    v.periods   = PeriodsReached(v.reload, now - v.anchor);
    v.pair_open = rtcl_latch_[ch].Open();
    return v;
}

uint16_t Vr41xxRtc::RtclCntHalfLocked(int ch, bool high) {
    const uint64_t       now = RtcTicksLocked();
    const Vr41xxRtclView v   = RtclViewLocked(ch, now);
    rephase_.OnCntRead(ch, v);
    const uint32_t count = DownCount(v.reload, now - v.anchor, kMask24);
    return static_cast<uint16_t>(high ? (count >> 16) & 0xFFu : count & 0xFFFFu);
}

void Vr41xxRtc::WriteEtimeHalfLocked(uint32_t half, uint16_t value) {
    if (!etime_latch_.Write(half, value)) return;
    etime_base_   = etime_latch_.Value();
    etime_anchor_ = RtcTicksLocked();
    if (ecmp_armed_) ArmEcmpLocked();
}

void Vr41xxRtc::WriteEcmpHalfLocked(uint32_t half, uint16_t value) {
    if (!ecmp_latch_.Write(half, value)) return;
    ecmp_       = ecmp_latch_.Value();
    ecmp_armed_ = true;
    ArmEcmpLocked();
}

/* RTCLnHREG D15:8 "Write 0 when writing"; "Any combined setting of "RTCL1HREG = 0x0000" and
   "RTCL1LREG = 0x0001, 0x0002, 0x0003, 0x0004" is prohibited." (VR4102 UM 16.2.3 p342, VR4121
   UM 17.2.3 / 17.2.5, VR4131 UM 13.2.3 p243). */
void Vr41xxRtc::WriteRtclHalfLocked(int ch, bool high, uint16_t value) {
    if (high && (value & 0xFF00u) != 0u) {
        emu_.Get<Fatal>().Die("Vr41xxRtc: RTCL%dHREG write 0x%04X sets reserved D15:8", ch + 1, value);
    }
    Vr41xxRtcLatch& latch  = rtcl_latch_[ch];
    const uint32_t  half   = high ? 1u : 0u;
    const bool      repeat = latch.Written(half);
    const uint64_t  now    = RtcTicksLocked();
    if (!latch.Open() || repeat) rephase_.OnPairStart(ch, repeat, now, RtclViewLocked(ch, now));
    if (!latch.Write(half, value)) return;
    const uint32_t reload = static_cast<uint32_t>(latch.Value());
    if (reload >= 1u && reload <= 4u) {
        emu_.Get<Fatal>().Die("Vr41xxRtc: RTCL%d set to the prohibited cycle %u", ch + 1, reload);
    }
    (ch == 0 ? rtcl1_reload_ : rtcl2_reload_)      = reload;
    (ch == 0 ? rtcl1_anchor_ : rtcl2_anchor_)      = now;
    (ch == 0 ? rtcl1_periods_ack_ : rtcl2_periods_ack_) = 0;
    RtclPairWrittenLocked(ch);
}

void Vr41xxRtc::WriteTclkHalfLocked(bool high, uint16_t value) {
    if (high && (value & 0xFE00u) != 0u) {
        emu_.Get<Fatal>().Die("Vr41xxRtc: TCLKHREG write 0x%04X sets reserved D15:9", value);
    }
    if (!tclk_latch_.Write(high ? 1u : 0u, value)) return;
    tclk_reload_ = static_cast<uint32_t>(tclk_latch_.Value());
    StartTclkLocked();
}

/* "The RTC Long1 timer begins its countdown at the value written to these registers. The
   setting is valid once values have been written to both registers." (VR4131 UM 13.2.3 p243,
   VR4121 UM 17.2.3) */
void Vr41xxRtc::RtclPairWrittenLocked(int ch) {
    const uint32_t reload = ch == 0 ? rtcl1_reload_ : rtcl2_reload_;
    const auto     grid   = rephase_.CompletePair(ch, reload);
    if (!grid) return;
    const uint64_t phase = RtcTicksLocked() - *grid;
    if (PeriodsReached(reload, phase) != 0u) {
        rephase_.OnReach(ch);
        return;
    }
    (ch == 0 ? rtcl1_anchor_ : rtcl2_anchor_) = *grid;
    rephase_.OnAbsorbed(ch, phase);
}

/* ---- RTC1 MMIO (0x0B0000C0) ---- */

uint16_t Vr41xxRtc::ReadHalf(uint32_t addr) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint32_t off = addr - MmioBase();
    switch (off) {
        case kEtimeL: return static_cast<uint16_t>(ReadEtimeLocked() & 0xFFFF);
        case kEtimeM: return static_cast<uint16_t>((ReadEtimeLocked() >> 16) & 0xFFFF);
        case kEtimeH: return static_cast<uint16_t>((ReadEtimeLocked() >> 32) & 0xFFFF);
        case kEcmpL:  return ecmp_latch_.Half(0u);
        case kEcmpM:  return ecmp_latch_.Half(1u);
        case kEcmpH:  return ecmp_latch_.Half(2u);
        case kRtcl1L: return rtcl_latch_[0].Half(0u);
        case kRtcl1H: return rtcl_latch_[0].Half(1u);
        case kRtcl2L: return rtcl_latch_[1].Half(0u);
        case kRtcl2H: return rtcl_latch_[1].Half(1u);
        case kRtcl1CntL: return RtclCntHalfLocked(0, false);
        case kRtcl1CntH: return RtclCntHalfLocked(0, true);
        case kRtcl2CntL: return RtclCntHalfLocked(1, false);
        case kRtcl2CntH: return RtclCntHalfLocked(1, true);
        default: HaltUnsupportedAccess("RTC ReadHalf", addr, 0);
    }
}

void Vr41xxRtc::WriteHalf(uint32_t addr, uint16_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint32_t off = addr - MmioBase();
    switch (off) {
        case kEtimeL: case kEtimeM: case kEtimeH:
            WriteEtimeHalfLocked((off - kEtimeL) / 2u, value);
            break;
        case kEcmpL: case kEcmpM: case kEcmpH:
            WriteEcmpHalfLocked((off - kEcmpL) / 2u, value);
            break;
        case kRtcl1L: WriteRtclHalfLocked(0, false, value); break;
        case kRtcl1H: WriteRtclHalfLocked(0, true, value);  break;
        case kRtcl2L: WriteRtclHalfLocked(1, false, value); break;
        case kRtcl2H: WriteRtclHalfLocked(1, true, value);  break;
        /* Count registers are read-only (UM Table 16-1). */
        case kRtcl1CntL: case kRtcl1CntH: case kRtcl2CntL: case kRtcl2CntH: return;
        default: HaltUnsupportedAccess("RTC WriteHalf", addr, value);
    }
    UpdateLocked();
}

uint32_t Vr41xxRtc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    return static_cast<uint32_t>(ReadHalf(MmioBase() + off)) |
           (static_cast<uint32_t>(ReadHalf(MmioBase() + off + 2)) << 16);
}
void Vr41xxRtc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    WriteHalf(MmioBase() + off,     static_cast<uint16_t>(value & 0xFFFF));
    WriteHalf(MmioBase() + off + 2, static_cast<uint16_t>(value >> 16));
}

/* ---- RTC2 MMIO (0x0B0001C0), via Vr41xxRtc2Mmio ---- */

uint16_t Vr41xxRtc::ReadHalf2(uint32_t off) {
    std::lock_guard<std::mutex> lk(mtx_);
    switch (off) {
        case kTclkL:    return tclk_latch_.Half(0u);
        case kTclkH:    return tclk_latch_.Half(1u);
        case kTclkCntL: return static_cast<uint16_t>(DownCount(tclk_reload_, TclkTicksLocked(), kMask25) & 0xFFFF);
        case kTclkCntH: return static_cast<uint16_t>((DownCount(tclk_reload_, TclkTicksLocked(), kMask25) >> 16) & 0x1FF);
        case kRtcIntReg: return rtcintreg_ & kRtcIntMask;
        default: HaltUnsupportedAccess("RTC2 ReadHalf", 0x0B0001C0u + off, 0);
    }
}
void Vr41xxRtc::WriteHalf2(uint32_t off, uint16_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    switch (off) {
        case kTclkL: WriteTclkHalfLocked(false, value); break;
        case kTclkH: WriteTclkHalfLocked(true, value);  break;
        case kTclkCntL: case kTclkCntH: return;   /* count registers read-only */
        case kRtcIntReg:
            AckIntBitsLocked(static_cast<uint16_t>(value & kRtcIntMask));
            break;
        default: HaltUnsupportedAccess("RTC2 WriteHalf", 0x0B0001C0u + off, value);
    }
    UpdateLocked();
}
uint32_t Vr41xxRtc::ReadWord2(uint32_t off) {
    return static_cast<uint32_t>(ReadHalf2(off)) |
           (static_cast<uint32_t>(ReadHalf2(off + 2)) << 16);
}
void Vr41xxRtc::WriteWord2(uint32_t off, uint32_t value) {
    WriteHalf2(off,     static_cast<uint16_t>(value & 0xFFFF));
    WriteHalf2(off + 2, static_cast<uint16_t>(value >> 16));
}

/* ---- hibernation ---- */

void Vr41xxRtc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    EvaluateLocked();
    const uint64_t now = RtcTicksLocked();
    const auto pos = [](uint32_t reload, uint64_t elapsed) {
        return reload != 0u ? static_cast<uint32_t>(elapsed % reload) : 0u;
    };
    w.Write("etime", ReadEtimeLocked());
    w.Write("ecmp", ecmp_); w.Write<uint8_t>("ecmp_programmed", ecmp_armed_ ? 1 : 0);
    w.Write("rtcl1_reload", rtcl1_reload_); w.Write("rtcl2_reload", rtcl2_reload_); w.Write("tclk_reload", tclk_reload_);
    w.Write("rtcl1_pos", pos(rtcl1_reload_, now - rtcl1_anchor_));
    w.Write("rtcl2_pos", pos(rtcl2_reload_, now - rtcl2_anchor_));
    w.Write("tclk_pos", pos(tclk_reload_, TclkTicksLocked()));
    w.Write("rtcintreg", rtcintreg_);
    etime_latch_.Save(w, "etime_latch", "etime_latch_written");
    ecmp_latch_.Save(w, "ecmp_latch", "ecmp_latch_written");
    rtcl_latch_[0].Save(w, "rtcl1_latch", "rtcl1_latch_written");
    rtcl_latch_[1].Save(w, "rtcl2_latch", "rtcl2_latch_written");
    tclk_latch_.Save(w, "tclk_latch", "tclk_latch_written");
    const Vr41xxRtclView views[2] = {RtclViewLocked(0, now), RtclViewLocked(1, now)};
    rephase_.Save(w, now, views);
}

void Vr41xxRtc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    uint64_t etime = 0;
    uint8_t  armed = 0;
    uint32_t rtcl1_pos = 0, rtcl2_pos = 0, tclk_pos = 0;
    r.Read("etime", etime);
    r.Read("ecmp", ecmp_); r.Read("ecmp_programmed", armed);
    r.Read("rtcl1_reload", rtcl1_reload_); r.Read("rtcl2_reload", rtcl2_reload_); r.Read("tclk_reload", tclk_reload_);
    r.Read("rtcl1_pos", rtcl1_pos); r.Read("rtcl2_pos", rtcl2_pos); r.Read("tclk_pos", tclk_pos);
    r.Read("rtcintreg", rtcintreg_);
    etime_latch_.Restore(r, "etime_latch", "etime_latch_written");
    ecmp_latch_.Restore(r, "ecmp_latch", "ecmp_latch_written");
    rtcl_latch_[0].Restore(r, "rtcl1_latch", "rtcl1_latch_written");
    rtcl_latch_[1].Restore(r, "rtcl2_latch", "rtcl2_latch_written");
    tclk_latch_.Restore(r, "tclk_latch", "tclk_latch_written");
    ecmp_armed_ = armed != 0u;

    rtcx_.Rebase();
    const uint64_t now = RtcTicksLocked();

    etime_base_   = etime;
    etime_anchor_ = now;
    if (ecmp_armed_) ArmEcmpLocked();
    rtcl1_anchor_      = now - rtcl1_pos;
    rtcl2_anchor_      = now - rtcl2_pos;
    rtcl1_periods_ack_ = PeriodsReached(rtcl1_reload_, rtcl1_pos);
    rtcl2_periods_ack_ = PeriodsReached(rtcl2_reload_, rtcl2_pos);
    tclk_restore_pos_  = tclk_pos;
    const Vr41xxRtclView views[2] = {RtclViewLocked(0, now), RtclViewLocked(1, now)};
    rephase_.Restore(r, now, views);
}

void Vr41xxRtc::PostRestore() {
    std::lock_guard<std::mutex> lk(mtx_);
    StartTclkLocked();
    tclk_anchor_cycle_ -= tclk_restore_pos_ * tclk_cycles_;
    tclk_periods_ack_   = PeriodsReached(tclk_reload_, tclk_restore_pos_);
    DriveIcuLocked();
    ArmNextLocked();
}
