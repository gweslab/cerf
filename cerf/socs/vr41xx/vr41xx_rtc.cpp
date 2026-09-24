#include "vr41xx_rtc.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../host/guest_deep_sleep.h"
#include "../../jit/guest_engine.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "vr41xx_icu.h"

#include <algorithm>
#include <chrono>
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

}  /* namespace */

void Vr41xxRtc::OnReady() {
    const Clock::time_point now = Clock::now();
    etime_anchor_ = rtcl1_anchor_ = rtcl2_anchor_ = tclk_anchor_ = now;
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
        EvaluateLocked();
        DriveIcuLocked();
    });

    worker_ = std::thread([this] { WorkerLoop(); });
}

/* Every RTC register's RTCRST column is 0 (UM 16.2.1-16.2.9). */
void Vr41xxRtc::ApplyRtcResetLocked() {
    const Clock::time_point now = Clock::now();
    etime_base_   = 0;
    etime_anchor_ = now;
    ecmp_         = 0;
    ecmp_armed_   = false;
    rtcl1_reload_ = 0; rtcl2_reload_ = 0; tclk_reload_ = 0;
    rtcl1_anchor_ = now; rtcl2_anchor_ = now; tclk_anchor_ = now;
    rtcl1_periods_ack_ = 0; rtcl2_periods_ack_ = 0; tclk_periods_ack_ = 0;
    rtcintreg_    = 0;
}

void Vr41xxRtc::StopTclkLocked() {
    tclk_reload_      = 0;
    tclk_anchor_      = Clock::now();
    tclk_periods_ack_ = 0;
    rtcintreg_        = static_cast<uint16_t>(rtcintreg_ & ~kIntTclk);
}

void Vr41xxRtc::AckIntBitsLocked(uint16_t clr) {
    rtcintreg_ = static_cast<uint16_t>(rtcintreg_ & ~clr);
    if (clr & kIntLong1) rtcl1_periods_ack_ = rtcl1_reload_ ? ElapsedTicksLocked(rtcl1_anchor_, kRtcHz) / rtcl1_reload_ : 0;
    if (clr & kIntLong2) rtcl2_periods_ack_ = rtcl2_reload_ ? ElapsedTicksLocked(rtcl2_anchor_, kRtcHz) / rtcl2_reload_ : 0;
    if (clr & kIntTclk)  tclk_periods_ack_  = tclk_reload_  ? ElapsedTicksLocked(tclk_anchor_, TClockHz()) / tclk_reload_ : 0;
}

/* ---- counting (wall-clock, computed on read; UM p338 elapsed, p344 RTCLong) ---- */

uint64_t Vr41xxRtc::ElapsedTicksLocked(Clock::time_point anchor, uint32_t hz) const {
    const auto d = Clock::now() - anchor;
    if (hz == kRtcHz)
        return static_cast<uint64_t>(std::chrono::duration_cast<
            std::chrono::duration<int64_t, std::ratio<1, 32768>>>(d).count());
    const int64_t ns  = std::chrono::duration_cast<std::chrono::nanoseconds>(d).count();
    const int64_t sec = ns / 1000000000;
    const int64_t rem = ns % 1000000000;
    return static_cast<uint64_t>(sec * hz + rem * hz / 1000000000);
}

uint64_t Vr41xxRtc::ReadEtimeLocked() const {
    return (etime_base_ + ElapsedTicksLocked(etime_anchor_, kRtcHz)) & kMask48;
}

/* A DOWN counter that reloads at 0x000001: value = reload - (elapsed mod reload),
   i.e. reload at elapsed%reload==0 counting down to 1 at elapsed%reload==reload-1.
   reload==0 means the unit is stopped (holds its reload=0 read). */
uint32_t Vr41xxRtc::ReadDownCountLocked(uint32_t reload, Clock::time_point anchor,
                                        uint32_t hz, uint32_t mask) const {
    if (reload == 0) return 0;
    const uint64_t pos = ElapsedTicksLocked(anchor, hz) % reload;
    return static_cast<uint32_t>(reload - pos) & mask;
}

/* ---- interrupt latch evaluation + ICU delivery ---- */

void Vr41xxRtc::EvaluateLocked() {
    /* Elapsed: fire once when ETIME reaches ECMP (equality; ETIME is monotonic up
       so >= with the armed flag yields a single latch, UM p338). */
    if (ecmp_armed_ && ReadEtimeLocked() >= ecmp_) {
        rtcintreg_ |= kIntElapsed;
        ecmp_armed_ = false;
    }
    /* RTCLong / TClock: latch on each new period boundary crossed since ack. */
    if (rtcl1_reload_) {
        const uint64_t p = ElapsedTicksLocked(rtcl1_anchor_, kRtcHz) / rtcl1_reload_;
        if (p > rtcl1_periods_ack_) rtcintreg_ |= kIntLong1;
    }
    if (rtcl2_reload_) {
        const uint64_t p = ElapsedTicksLocked(rtcl2_anchor_, kRtcHz) / rtcl2_reload_;
        if (p > rtcl2_periods_ack_) rtcintreg_ |= kIntLong2;
    }
    if (tclk_reload_) {
        const uint64_t p = ElapsedTicksLocked(tclk_anchor_, TClockHz()) / tclk_reload_;
        if (p > tclk_periods_ack_) rtcintreg_ |= kIntTclk;
    }
}

void Vr41xxRtc::DriveIcuLocked() {
    auto& icu = emu_.Get<Vr41xxIcu>();
    icu.SetSysint1Source(1u << 3, (rtcintreg_ & kIntElapsed) != 0);   /* ETIMER  */
    icu.SetSysint1Source(1u << 2, (rtcintreg_ & kIntLong1)   != 0);   /* RTCL1   */
    icu.SetSysint2Source(1u << 0, (rtcintreg_ & kIntLong2)   != 0);   /* RTCL2   */
    icu.SetSysint2Source(1u << 3, (rtcintreg_ & kIntTclk)    != 0);   /* TCLK    */
}

/* ---- RTC1 MMIO (0x0B0000C0) ---- */

uint16_t Vr41xxRtc::ReadHalf(uint32_t addr) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint32_t off = addr - MmioBase();
    switch (off) {
        case kEtimeL: return static_cast<uint16_t>(ReadEtimeLocked() & 0xFFFF);
        case kEtimeM: return static_cast<uint16_t>((ReadEtimeLocked() >> 16) & 0xFFFF);
        case kEtimeH: return static_cast<uint16_t>((ReadEtimeLocked() >> 32) & 0xFFFF);
        case kEcmpL:  return static_cast<uint16_t>(ecmp_ & 0xFFFF);
        case kEcmpM:  return static_cast<uint16_t>((ecmp_ >> 16) & 0xFFFF);
        case kEcmpH:  return static_cast<uint16_t>((ecmp_ >> 32) & 0xFFFF);
        case kRtcl1L: return static_cast<uint16_t>(rtcl1_reload_ & 0xFFFF);
        case kRtcl1H: return static_cast<uint16_t>((rtcl1_reload_ >> 16) & 0xFF);
        case kRtcl2L: return static_cast<uint16_t>(rtcl2_reload_ & 0xFFFF);
        case kRtcl2H: return static_cast<uint16_t>((rtcl2_reload_ >> 16) & 0xFF);
        case kRtcl1CntL: return static_cast<uint16_t>(ReadDownCountLocked(rtcl1_reload_, rtcl1_anchor_, kRtcHz, kMask24) & 0xFFFF);
        case kRtcl1CntH: return static_cast<uint16_t>((ReadDownCountLocked(rtcl1_reload_, rtcl1_anchor_, kRtcHz, kMask24) >> 16) & 0xFF);
        case kRtcl2CntL: return static_cast<uint16_t>(ReadDownCountLocked(rtcl2_reload_, rtcl2_anchor_, kRtcHz, kMask24) & 0xFFFF);
        case kRtcl2CntH: return static_cast<uint16_t>((ReadDownCountLocked(rtcl2_reload_, rtcl2_anchor_, kRtcHz, kMask24) >> 16) & 0xFF);
        default: HaltUnsupportedAccess("RTC ReadHalf", addr, 0);
    }
}

void Vr41xxRtc::WriteHalf(uint32_t addr, uint16_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint32_t off = addr - MmioBase();
    switch (off) {
        /* ETIME write is valid only once all of L/M/H have been written (UM p338);
           re-anchor so the new time counts forward from now. */
        case kEtimeL: etime_base_ = (etime_base_ & ~0xFFFFull) | value; break;
        case kEtimeM: etime_base_ = (etime_base_ & ~0xFFFF0000ull) | (uint64_t(value) << 16); break;
        case kEtimeH: etime_base_ = (etime_base_ & ~0xFFFF00000000ull) | (uint64_t(value) << 32);
                      etime_base_ &= kMask48; etime_anchor_ = Clock::now(); break;
        case kEcmpL:  ecmp_ = (ecmp_ & ~0xFFFFull) | value; break;
        case kEcmpM:  ecmp_ = (ecmp_ & ~0xFFFF0000ull) | (uint64_t(value) << 16); break;
        case kEcmpH:  ecmp_ = ((ecmp_ & ~0xFFFF00000000ull) | (uint64_t(value) << 32)) & kMask48;
                      ecmp_armed_ = true; break;   /* re-arm the one-shot alarm */
        case kRtcl1L: rtcl1_reload_ = (rtcl1_reload_ & ~0xFFFFu) | value; rtcl1_anchor_ = Clock::now(); rtcl1_periods_ack_ = 0; break;
        case kRtcl1H: rtcl1_reload_ = ((rtcl1_reload_ & ~0xFF0000u) | (uint32_t(value & 0xFF) << 16)) & kMask24; rtcl1_anchor_ = Clock::now(); rtcl1_periods_ack_ = 0; break;
        case kRtcl2L: rtcl2_reload_ = (rtcl2_reload_ & ~0xFFFFu) | value; rtcl2_anchor_ = Clock::now(); rtcl2_periods_ack_ = 0; break;
        case kRtcl2H: rtcl2_reload_ = ((rtcl2_reload_ & ~0xFF0000u) | (uint32_t(value & 0xFF) << 16)) & kMask24; rtcl2_anchor_ = Clock::now(); rtcl2_periods_ack_ = 0; break;
        /* Count registers are read-only (UM Table 16-1). */
        case kRtcl1CntL: case kRtcl1CntH: case kRtcl2CntL: case kRtcl2CntH: return;
        default: HaltUnsupportedAccess("RTC WriteHalf", addr, value);
    }
    EvaluateLocked();
    DriveIcuLocked();
    NotifyWorker();
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
        case kTclkL:    return static_cast<uint16_t>(tclk_reload_ & 0xFFFF);
        case kTclkH:    return static_cast<uint16_t>((tclk_reload_ >> 16) & 0x1FF);
        case kTclkCntL: return static_cast<uint16_t>(ReadDownCountLocked(tclk_reload_, tclk_anchor_, TClockHz(), kMask25) & 0xFFFF);
        case kTclkCntH: return static_cast<uint16_t>((ReadDownCountLocked(tclk_reload_, tclk_anchor_, TClockHz(), kMask25) >> 16) & 0x1FF);
        case kRtcIntReg: return rtcintreg_ & kRtcIntMask;
        default: HaltUnsupportedAccess("RTC2 ReadHalf", 0x0B0001C0u + off, 0);
    }
}
void Vr41xxRtc::WriteHalf2(uint32_t off, uint16_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    switch (off) {
        case kTclkL: tclk_reload_ = (tclk_reload_ & ~0xFFFFu) | value; tclk_anchor_ = Clock::now(); tclk_periods_ack_ = 0;
                     if (tclk_reload_ && TClockHz() == 0) HaltUnsupportedAccess("RTC TClock frequency ungrounded (CLKSPEEDREG not modeled)", 0x0B0001C0u, tclk_reload_);
                     break;
        case kTclkH: tclk_reload_ = ((tclk_reload_ & ~0x1FF0000u) | (uint32_t(value & 0x1FF) << 16)) & kMask25; tclk_anchor_ = Clock::now(); tclk_periods_ack_ = 0;
                     if (tclk_reload_ && TClockHz() == 0) HaltUnsupportedAccess("RTC TClock frequency ungrounded (CLKSPEEDREG not modeled)", 0x0B0001C2u, tclk_reload_);
                     break;
        case kTclkCntL: case kTclkCntH: return;   /* count registers read-only */
        case kRtcIntReg:
            AckIntBitsLocked(static_cast<uint16_t>(value & kRtcIntMask));
            break;
        default: HaltUnsupportedAccess("RTC2 WriteHalf", 0x0B0001C0u + off, value);
    }
    EvaluateLocked();
    DriveIcuLocked();
    NotifyWorker();
}
uint32_t Vr41xxRtc::ReadWord2(uint32_t off) {
    return static_cast<uint32_t>(ReadHalf2(off)) |
           (static_cast<uint32_t>(ReadHalf2(off + 2)) << 16);
}
void Vr41xxRtc::WriteWord2(uint32_t off, uint32_t value) {
    WriteHalf2(off,     static_cast<uint16_t>(value & 0xFFFF));
    WriteHalf2(off + 2, static_cast<uint16_t>(value >> 16));
}

/* ---- worker: re-evaluate latches on the guest-visible cadence ---- */

void Vr41xxRtc::NotifyWorker() { std::lock_guard<std::mutex> g(cv_mtx_); cv_.notify_all(); }
void Vr41xxRtc::StopWorker() {
    stop_.store(true, std::memory_order_release);
    NotifyWorker();
    if (worker_.joinable()) worker_.join();
}

void Vr41xxRtc::WorkerLoop() {
    auto& freeze = emu_.Get<EmulationFreeze>();
    auto& engine = emu_.Get<GuestEngine>();
    std::unique_lock<std::mutex> lk(cv_mtx_);
    while (!stop_.load(std::memory_order_acquire)) {
        lk.unlock();
        {
            auto frozen = freeze.WorkerSection();
            bool elapsed_pending = false;
            {
                std::lock_guard<std::mutex> sl(mtx_);
                EvaluateLocked();
                DriveIcuLocked();
                elapsed_pending = (rtcintreg_ & kIntElapsed) != 0;
            }
            /* Hibernate startup factor "an Elapsed Time timer interrupt" (VR4131 UM
               U15350EJ2V0UM 12.1.3 p216); a match pending at HIBERNATE entry wakes
               immediately - the guest arms ECMP = ETIME - 4 at 0x9F0359B0. */
            if (elapsed_pending && engine.DeepSleep() && !engine.ResetPending())
                emu_.Get<GuestDeepSleep>().RequestHardwareWake();
        }
        lk.lock();
        if (stop_.load(std::memory_order_acquire)) break;
        cv_.wait_for(lk, std::chrono::milliseconds(1));
    }
}

/* ---- hibernation ---- */

void Vr41xxRtc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write("etime", ReadEtimeLocked());
    w.Write("ecmp", ecmp_); w.Write<uint8_t>("ecmp_armed", ecmp_armed_ ? 1 : 0);
    w.Write("rtcl1_reload", rtcl1_reload_); w.Write("rtcl2_reload", rtcl2_reload_); w.Write("tclk_reload", tclk_reload_);
    w.Write("rtcintreg", rtcintreg_);
}
void Vr41xxRtc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    r.Read("etime", etime_base_); etime_base_ &= kMask48;
    uint8_t armed = 0; r.Read("ecmp", ecmp_); r.Read("ecmp_armed", armed); ecmp_armed_ = armed != 0;
    r.Read("rtcl1_reload", rtcl1_reload_); r.Read("rtcl2_reload", rtcl2_reload_); r.Read("tclk_reload", tclk_reload_);
    r.Read("rtcintreg", rtcintreg_); rtcintreg_ &= kRtcIntMask;
    const Clock::time_point now = Clock::now();   /* never raw-serialize a time_point */
    etime_anchor_ = rtcl1_anchor_ = rtcl2_anchor_ = tclk_anchor_ = now;
    rtcl1_periods_ack_ = rtcl2_periods_ack_ = tclk_periods_ack_ = 0;
}
void Vr41xxRtc::PostRestore() {
    std::lock_guard<std::mutex> lk(mtx_);
    DriveIcuLocked();   /* re-assert the restored RTC interrupt levels into the ICU */
}
