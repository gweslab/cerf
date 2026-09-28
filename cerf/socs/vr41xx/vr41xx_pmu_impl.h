#pragma once

#include "vr41xx_giu.h"
#include "vr41xx_pmu.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../host/guest_deep_sleep.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <atomic>
#include <cstdint>

namespace cerf_vr41xx_pmu_detail {

constexpr uint32_t kOffIntReg  = 0x00u;
constexpr uint32_t kOffCntReg  = 0x02u;
constexpr uint32_t kOffWaitReg = 0x08u;

/* PMUINTREG D9 RTCINTR "RTC alarm interrupt detection", D10 DCDST "DCD# pin state"
   (VR4102 UM 15.2.1 p328); GIUIOSELL: "GPIO15 (DCD#) is fixed as input" (VR4102 UM
   18.2.1, VR4121 UM 19.2.1). */
constexpr uint16_t kIntRtcIntr = 0x0200u;
constexpr uint16_t kIntDcdSt   = 0x0400u;
constexpr int      kDcdPin     = 15;

/* PMUCNTREG "Other resets" row: D15-8 "Holds the value before reset", D7-0 as RTCRST
   (VR4102 UM 15.2.2 p330, VR4111 UM 16.2.2 p366, VR4121 UM 16.2.2 p411, VR4131 UM 12.2.2 p227). */
constexpr uint16_t kCntHeldOnReset = 0xFF00u;

struct Vr41xxPmuModel {
    uint32_t base;
    uint32_t size;
    uint16_t int_w1c;
    uint16_t int_sw_rw;
    uint16_t int_power_on;
    uint16_t cnt_writable;
    uint16_t cnt_fixed_read;
    uint16_t cnt_power_on;
    uint16_t wait_wmask;
    uint16_t wait_power_on;
    uint16_t int_warm_cause;
    uint16_t int_cold_cause;
    uint16_t int_power_wake;
    uint16_t cnt_write_zero = 0;
    uint16_t cnt_write_one  = 0;
    /* VR4131 UM 12.2.1 p225, PMUINTREG "After reset", Note 1: "Holds the value before
       reset." */
    uint16_t int_held_on_reset  = 0xFFFFu;
    uint16_t int_watchdog_cause = 0;
};

template <const std::string_view& Soc, Vr41xxPmuModel M>
class Vr41xxPmuBase : public Vr41xxPmu, public ResetCauseLatch, public DeepSleepWaker {
public:
    using Vr41xxPmu::Vr41xxPmu;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == Soc;
    }

    /* An RTC reset "resets all peripheral units including the RTC unit"; an RSTSW
       reset "resets all peripheral units except for RTC and PMU" (VR4111 UM
       16.1.1(1)/(2), Table 16-1). */
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().SetCauseLatch(this);
        auto& sleep = emu_.Get<GuestDeepSleep>();
        sleep.RegisterWaker(this);
        sleep.RegisterSleepEntryListener([this] {
            wake_pending_.store(false, std::memory_order_release);
            hibernating_.store(true, std::memory_order_release);
        });
        sleep.RegisterParkWakeSource([this] {
            return wake_pending_.load(std::memory_order_acquire);
        });
        if (M.int_power_wake != 0u) {
            sleep.RegisterUserWakeInput([this] { SetIntBits(M.int_power_wake); });
        }
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
            hibernating_.store(false, std::memory_order_release);
            wake_pending_.store(false, std::memory_order_release);
            const uint16_t cause = pending_cause_.exchange(0u, std::memory_order_acq_rel);
            if (kind != ResetLineKind::Rtc) {
                const uint16_t kept = emu_.Get<GuestCpuReset>().DeliveredResetWasResume()
                    ? IntReg()
                    : static_cast<uint16_t>(IntReg() & M.int_held_on_reset);
                StoreIntReg(static_cast<uint16_t>(kept | cause));
                const uint16_t held = cntreg_.load(std::memory_order_acquire) & kCntHeldOnReset;
                cntreg_.store(static_cast<uint16_t>(held | (M.cnt_power_on & ~kCntHeldOnReset)),
                              std::memory_order_release);
                return;
            }
            StoreIntReg(static_cast<uint16_t>(M.int_power_on | cause));
            cntreg_.store(M.cnt_power_on, std::memory_order_release);
            waitreg_ = M.wait_power_on;
            ResetExt();
        });
    }

    uint32_t MmioBase() const override { return M.base; }
    uint32_t MmioSize() const override { return M.size; }

    void LatchWarmReset() override { LatchResetCause(M.int_warm_cause); }
    void LatchColdReset() override { LatchResetCause(M.int_cold_cause); }
    void LatchWatchdogReset() override { LatchResetCause(M.int_watchdog_cause); }

    void LatchSleepWakeCause() override {}
    void ClearSleepWakeCause() override { ClearIntBits(M.int_power_wake); }

    void OnGpioLevel(int pin, bool prev, bool level) override {
        if (prev == level || !hibernating_.load(std::memory_order_acquire)) return;
        if (pin == kDcdPin) {
            if (!level) wake_pending_.store(true, std::memory_order_release);
            return;
        }
        uint16_t cnt = 0;
        int      bit = 0;
        if (pin >= 0 && pin <= 3) {
            cnt = cntreg_.load(std::memory_order_acquire);
            bit = pin;
        } else if (pin >= 9 && pin <= 12) {
            cnt = ActivationControl2();
            bit = pin - 9;
        } else {
            return;
        }
        const uint16_t msk = static_cast<uint16_t>(1u << (12 + bit));
        const uint16_t trg = static_cast<uint16_t>(1u << (8 + bit));
        if ((cnt & msk) == 0u) return;
        if (((cnt & trg) != 0u) == level) return;
        if (pin <= 3) SetIntBits(msk);
        else          LatchActivation2(msk);
        wake_pending_.store(true, std::memory_order_release);
    }

    void LatchRtcAlarmWake() override { SetIntBits(kIntRtcIntr); }

    uint16_t ReadHalf(uint32_t addr) override {
        switch (addr - M.base) {
            case kOffIntReg:
                return static_cast<uint16_t>(
                    IntReg() | (emu_.Get<Vr41xxGiu>().GetPinLevel(kDcdPin) ? kIntDcdSt : 0u));
            case kOffCntReg: return cntreg_.load(std::memory_order_acquire);
            default: return ReadHalfExt(addr);
        }
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        switch (addr - M.base) {
            case kOffIntReg: AckIntReg(value); return;
            case kOffCntReg:
                if ((value & M.cnt_write_zero) != 0u ||
                    (value & M.cnt_write_one) != M.cnt_write_one) {
                    emu_.Get<Fatal>().Die("Vr41xxPmu: PMUCNTREG write 0x%04X breaks the "
                                          "write-0 / write-1 rule of its reserved bits", value);
                }
                cntreg_.store(static_cast<uint16_t>((value & M.cnt_writable) | M.cnt_fixed_read),
                              std::memory_order_release);
                return;
            case kOffWaitReg:
                if (M.wait_wmask == 0u) break;
                waitreg_ = static_cast<uint16_t>(value & M.wait_wmask);
                return;
            default: break;
        }
        WriteHalfExt(addr, value);
    }

    void SaveState(StateWriter& w) override {
        w.Write("int_reg", IntReg());
        w.Write("cntreg", cntreg_.load(std::memory_order_acquire));
        w.Write("waitreg", waitreg_);
        w.Write<uint8_t>("hibernating", hibernating_.load(std::memory_order_acquire) ? 1u : 0u);
        w.Write<uint8_t>("wake_pending", wake_pending_.load(std::memory_order_acquire) ? 1u : 0u);
        w.Write("pending_cause", pending_cause_.load(std::memory_order_acquire));
    }

    void RestoreState(StateReader& r) override {
        uint16_t v = 0, cnt = 0;
        uint8_t  hib = 0, pend = 0;
        r.Read("int_reg", v);
        r.Read("cntreg", cnt);
        r.Read("waitreg", waitreg_);
        r.Read("hibernating", hib);
        r.Read("wake_pending", pend);
        if (hib > 1u || pend > 1u) {
            r.Reject("Vr41xxPmu: hibernation flag %u or wake latch %u out of range", hib, pend);
        }
        const bool wait_bad = M.wait_wmask != 0u ? (waitreg_ & ~M.wait_wmask) != 0u
                                                 : waitreg_ != M.wait_power_on;
        if ((v & ~(M.int_w1c | M.int_sw_rw)) != 0u ||
            static_cast<uint16_t>(cnt & ~M.cnt_writable) != M.cnt_fixed_read || wait_bad) {
            r.Reject("Vr41xxPmu: restored PMUINTREG 0x%04X, PMUCNTREG 0x%04X or PMUWAITREG "
                     "0x%04X holds a value no register write stores", v, cnt, waitreg_);
        }
        uint16_t cause = 0;
        r.Read("pending_cause", cause);
        if ((cause & ~(M.int_warm_cause | M.int_cold_cause | M.int_watchdog_cause)) != 0u) {
            r.Reject("Vr41xxPmu: pending reset cause 0x%04X is no reset's cause bits", cause);
        }
        pending_cause_.store(cause, std::memory_order_release);
        intreg_.store(v, std::memory_order_release);
        cntreg_.store(cnt, std::memory_order_release);
        hibernating_.store(hib != 0u, std::memory_order_release);
        wake_pending_.store(pend != 0u, std::memory_order_release);
    }

protected:
    /* Registers one chip of the family carries and the other does not (VR4121 UM
       Table 1-6 adds PMUWAITREG and PMUDIVREG over VR4102 UM Table 15-4). */
    virtual uint16_t ReadHalfExt(uint32_t addr) { return Peripheral::ReadHalf(addr); }
    virtual void WriteHalfExt(uint32_t addr, uint16_t value) {
        Peripheral::WriteHalf(addr, value);
    }
    virtual void ResetExt() {}

    virtual uint16_t ActivationControl2() const { return 0u; }
    virtual void LatchActivation2(uint16_t bits) {
        emu_.Get<Fatal>().Die("Vr41xxPmu: GPIO(12:9) activation 0x%04X on a chip without "
                              "PMUCNT2REG", bits);
    }

    uint16_t IntReg() const { return intreg_.load(std::memory_order_acquire); }

    void AckIntReg(uint16_t value) {
        uint16_t cur = intreg_.load(std::memory_order_acquire), next;
        do {
            next = static_cast<uint16_t>((cur & ~(value & M.int_w1c) & ~M.int_sw_rw)
                                         | (value & M.int_sw_rw));
        } while (!intreg_.compare_exchange_weak(cur, next, std::memory_order_acq_rel));
    }

    void SetIntBits(uint16_t bits) {
        intreg_.fetch_or(bits, std::memory_order_acq_rel);
    }

    void ClearIntBits(uint16_t bits) {
        intreg_.fetch_and(static_cast<uint16_t>(~bits), std::memory_order_acq_rel);
    }

    void StoreIntReg(uint16_t value) { intreg_.store(value, std::memory_order_release); }

    void LatchResetCause(uint16_t bits) {
        pending_cause_.fetch_or(bits, std::memory_order_acq_rel);
    }

    std::atomic<uint16_t> intreg_{M.int_power_on};
    std::atomic<uint16_t> pending_cause_{0};
    std::atomic<uint16_t> cntreg_{M.cnt_power_on};
    uint16_t              waitreg_ = M.wait_power_on;
    std::atomic<bool>     hibernating_{false};
    std::atomic<bool>     wake_pending_{false};
};

}
