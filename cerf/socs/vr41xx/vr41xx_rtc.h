#pragma once

#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_base.h"
#include "vr41xx_rtc_latch.h"
#include "vr41xx_rtcl_rephase.h"
#include "vr41xx_rtcx_ticks.h"

#include <cstdint>
#include <mutex>

class MipsCoreClock;
class MipsInterruptChannel;

/* NEC VR41xx RTC, VR4102 UM ch.16 == VR4111 UM ch.17 == VR4121 UM ch.17 (VR4102 Table 16-1,
   VR4111 Table 17-1 p372, VR4121 Table 17-1); RTC1 block 0x0B0000C0, RTC2 block 0x0B0001C0. */
class Vr41xxRtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    void OnReady() override;

    uint32_t MmioBase() const override { return 0x0B0000C0u; }   /* RTC1 block */
    uint32_t MmioSize() const override { return 0x20u; }         /* 0xC0-0xDF   */

    uint16_t ReadHalf(uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;
    uint8_t  ReadByte(uint32_t addr) override { HaltUnsupportedAccess("RTC ReadByte", addr, 0); }
    void     WriteByte(uint32_t addr, uint8_t v) override { HaltUnsupportedAccess("RTC WriteByte", addr, v); }

    /* RTC2 block (0x0B0001C0) accessors, driven by the Vr41xxRtc2Mmio adapter. */
    uint16_t ReadHalf2(uint32_t off);
    void     WriteHalf2(uint32_t off, uint16_t value);
    uint32_t ReadWord2(uint32_t off);
    void     WriteWord2(uint32_t off, uint32_t value);

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    static constexpr uint64_t kMask48    = 0xFFFFFFFFFFFFull;
    static constexpr uint32_t kMask24    = 0x00FFFFFFu;
    static constexpr uint32_t kMask25    = 0x01FFFFFFu;

    /* RTCINTREG D0-D3 latch bits (VR4102 UM 16.2.9 p353 == VR4111 UM 17.2.9 p389 ==
       VR4121 UM 17.2.9 p437); each comment names the ICU direct source it routes to
       per SYSINT1REG / SYSINT2REG. */
    static constexpr uint16_t kIntElapsed = 1u << 0;    /* RTCINTR0 -> SYSINT1 D3 (ETIMERINTR) */
    static constexpr uint16_t kIntLong1   = 1u << 1;    /* RTCINTR1 -> SYSINT1 D2 (RTCL1INTR)  */
    static constexpr uint16_t kIntLong2   = 1u << 2;    /* RTCINTR2 -> SYSINT2 D0 (RTCL2INTR)  */
    static constexpr uint16_t kIntTclk    = 1u << 3;    /* RTCINTR3 -> SYSINT2 D3 (TCLKINTR)   */

    uint64_t RtcTicksLocked();
    uint64_t TclkCyclesLocked() const;
    uint64_t TclkTicksLocked() const;
    uint64_t ReadEtimeLocked();
    static uint32_t DownCount(uint32_t reload, uint64_t elapsed, uint32_t mask);
    static uint64_t PeriodsReached(uint32_t reload, uint64_t elapsed);

    void     ApplyRtcResetLocked();
    void     StopTclkLocked();
    void     StartTclkLocked();
    void     AckIntBitsLocked(uint16_t clr);
    void     ArmEcmpLocked();
    void     EvaluateLocked();
    void     DriveIcuLocked();
    void     ArmNextLocked();
    void     UpdateLocked();
    void     OnRateChange();
    Vr41xxRtclView RtclViewLocked(int ch, uint64_t now);
    uint16_t RtclCntHalfLocked(int ch, bool high);
    void     WriteEtimeHalfLocked(uint32_t half, uint16_t value);
    void     WriteEcmpHalfLocked(uint32_t half, uint16_t value);
    void     WriteRtclHalfLocked(int ch, bool high, uint16_t value);
    void     WriteTclkHalfLocked(bool high, uint16_t value);
    void     RtclPairWrittenLocked(int ch);

    mutable std::mutex mtx_;

    GuestCycleClock*        clock_      = nullptr;
    GuestCycleClock::Event* event_      = nullptr;
    MipsCoreClock*          core_clock_ = nullptr;
    MipsInterruptChannel*   channel_    = nullptr;
    Vr41xxRtcxTicks         rtcx_{emu_, Vr41xxRtcxDomain::RtcIcuPmu};

    uint64_t etime_base_   = 0;
    uint64_t etime_anchor_ = 0;
    uint64_t ecmp_         = 0;
    bool     ecmp_armed_   = false;
    uint64_t ecmp_match_   = 0;

    uint32_t rtcl1_reload_      = 0;
    uint32_t rtcl2_reload_      = 0;
    uint32_t tclk_reload_       = 0;
    uint64_t rtcl1_anchor_      = 0;
    uint64_t rtcl2_anchor_      = 0;
    uint64_t tclk_anchor_cycle_ = 0;
    uint64_t tclk_cycles_       = 1;
    uint64_t tclk_restore_pos_  = 0;
    uint64_t rtcl1_periods_ack_ = 0;
    uint64_t rtcl2_periods_ack_ = 0;
    uint64_t tclk_periods_ack_  = 0;

    uint16_t rtcintreg_ = 0;

    Vr41xxRtcLatch etime_latch_{3u, kMask48};
    Vr41xxRtcLatch ecmp_latch_{3u, kMask48};
    Vr41xxRtcLatch rtcl_latch_[2] = {{2u, kMask24}, {2u, kMask24}};
    Vr41xxRtcLatch tclk_latch_{2u, kMask25};

    Vr41xxRtclRephase rephase_;
};
