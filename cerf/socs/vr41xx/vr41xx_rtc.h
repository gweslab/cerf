#pragma once

#include "../../peripherals/peripheral_base.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

/* NEC VR41xx RTC, VR4102 UM ch.16 == VR4111 UM ch.17 == VR4121 UM ch.17 (VR4102 Table 16-1,
   VR4111 Table 17-1 p372, VR4121 Table 17-1); RTC1 block 0x0B0000C0, RTC2 block 0x0B0001C0. */
class Vr41xxRtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    ~Vr41xxRtc() override { StopWorker(); }
    void OnShutdown() override { StopWorker(); }

    void OnReady() override;

    /* CLKSPEEDREG: VR4102 UM 10.2.8 p245, VR4111 UM 11.2.8 p273, VR4121 UM 11.2.10 p291. */
    virtual uint32_t TClockHz() const = 0;

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
    using Clock = std::chrono::steady_clock;

    static constexpr uint64_t kMask48    = 0xFFFFFFFFFFFFull;
    static constexpr uint32_t kMask24    = 0x00FFFFFFu;
    static constexpr uint32_t kMask25    = 0x01FFFFFFu;
    static constexpr uint32_t kRtcHz     = 32768u;      /* elapsed + long timers */

    /* RTCINTREG D0-D3 latch bits (VR4102 UM 16.2.9 p353 == VR4111 UM 17.2.9 p389 ==
       VR4121 UM 17.2.9 p437); each comment names the ICU direct source it routes to
       per SYSINT1REG / SYSINT2REG. */
    static constexpr uint16_t kIntElapsed = 1u << 0;    /* RTCINTR0 -> SYSINT1 D3 (ETIMERINTR) */
    static constexpr uint16_t kIntLong1   = 1u << 1;    /* RTCINTR1 -> SYSINT1 D2 (RTCL1INTR)  */
    static constexpr uint16_t kIntLong2   = 1u << 2;    /* RTCINTR2 -> SYSINT2 D0 (RTCL2INTR)  */
    static constexpr uint16_t kIntTclk    = 1u << 3;    /* RTCINTR3 -> SYSINT2 D3 (TCLKINTR)   */

    uint64_t ElapsedTicksLocked(Clock::time_point anchor, uint32_t hz) const;
    uint64_t ReadEtimeLocked() const;
    uint32_t ReadDownCountLocked(uint32_t reload, Clock::time_point anchor,
                                 uint32_t hz, uint32_t mask) const;

    void     ApplyRtcResetLocked();     /* RTCRST: every register takes its reset column */
    void     StopTclkLocked();          /* non-RTCRST reset: TCLK period/count/latch = 0 */
    void     AckIntBitsLocked(uint16_t clr);   /* W1C a cause + ack its period counter */
    void     EvaluateLocked();          /* update the four RTCINTR latches */
    void     DriveIcuLocked();          /* push RTCINTREG bits to the ICU  */
    void     NotifyWorker();
    void     StopWorker();
    void     WorkerLoop();

    mutable std::mutex mtx_;

    /* Elapsed-time up counter + one-shot compare alarm. */
    uint64_t          etime_base_   = 0;                /* value at etime_anchor_ */
    Clock::time_point etime_anchor_ = {};
    uint64_t          ecmp_         = 0;
    bool              ecmp_armed_   = false;            /* fires once per ECMP write */

    /* Two RTCLong down counters + one TClock down counter (reload=0 stops). */
    uint32_t          rtcl1_reload_ = 0;
    uint32_t          rtcl2_reload_ = 0;
    uint32_t          tclk_reload_  = 0;
    Clock::time_point rtcl1_anchor_ = {};
    Clock::time_point rtcl2_anchor_ = {};
    Clock::time_point tclk_anchor_  = {};
    uint64_t          rtcl1_periods_ack_ = 0;          /* period count acknowledged (W1C) */
    uint64_t          rtcl2_periods_ack_ = 0;
    uint64_t          tclk_periods_ack_  = 0;

    uint16_t          rtcintreg_ = 0;                  /* RTCINTREG latches (W1C) */

    std::mutex              cv_mtx_;
    std::condition_variable cv_;
    std::thread             worker_;
    std::atomic<bool>       stop_{false};
};
