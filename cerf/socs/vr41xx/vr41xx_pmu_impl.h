#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../host/guest_deep_sleep.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <atomic>
#include <cstdint>

namespace cerf_vr41xx_pmu_detail {

constexpr uint32_t kOffIntReg  = 0x00u;   /* PMUINTREG  */
constexpr uint32_t kOffCntReg  = 0x02u;   /* PMUCNTREG  */
constexpr uint32_t kOffWaitReg = 0x08u;   /* PMUWAITREG */

/* Every value is per-chip: the two registers' bit layouts coincide across the
   family, but VR4121 UM 16.2.1 names D7:6 memo(1:0) ("can be used by users
   freely") where VR4102 UM 15.2.1 names them BATTLOCK/CARDLOCK. */
struct Vr41xxPmuModel {
    uint32_t base;
    uint32_t size;
    uint16_t int_w1c;         /* PMUINTREG: "Cleared to 0 when 1 is written"  */
    uint16_t int_sw_rw;       /* PMUINTREG: software R/W, never hardware-set  */
    uint16_t int_power_on;    /* PMUINTREG: RTCRST column                     */
    uint16_t cnt_writable;    /* PMUCNTREG: R/W bits                          */
    uint16_t cnt_fixed_read;  /* PMUCNTREG: reserved bits that read 1         */
    uint16_t cnt_power_on;    /* PMUCNTREG: RTCRST column                     */
    uint16_t wait_wmask;      /* PMUWAITREG@0x08: WCOUNT R/W bits (VR4111 UM 16.2.5) */
    uint16_t wait_power_on;   /* PMUWAITREG@0x08: RTCRST column (VR4111 UM 16.2.5)   */
    uint16_t int_warm_cause;  /* PMUINTREG: RSTSW-reset cause bit                    */
    uint16_t int_cold_cause;  /* PMUINTREG: RTC-reset cause bit                      */
};

/* "When the software executes the HIBERNATE instruction, the VR4102 ... enters reset status ...
   A reset by software shutdown initializes the entire internal state except for the RTC timer
   and the PMU ... the processor ... begins the Cold reset exception sequence to access the reset
   vectors in the ROM space" (VR4102 UM 7.1.4 + Fig 7-4, VR4121 UM 8.1.4 + Fig 8-6). */
template <const std::string_view& Soc, Vr41xxPmuModel M>
class Vr41xxPmuBase : public Peripheral, public ResetCauseLatch, public DeepSleepWaker {
public:
    using Peripheral::Peripheral;

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
        emu_.Get<GuestDeepSleep>().RegisterWaker(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
            if (kind != ResetLineKind::Rtc) return;
            StoreIntReg(M.int_power_on);
            cntreg_  = M.cnt_power_on;
            waitreg_ = M.wait_power_on;
            ResetExt();
        });
    }

    uint32_t MmioBase() const override { return M.base; }
    uint32_t MmioSize() const override { return M.size; }

    void LatchWarmReset() override { SetIntBits(M.int_warm_cause); }
    void LatchColdReset() override { SetIntBits(M.int_cold_cause); }

    uint16_t ReadHalf(uint32_t addr) override {
        switch (addr - M.base) {
            case kOffIntReg: return IntReg();
            case kOffCntReg: return cntreg_;
            default: return ReadHalfExt(addr);
        }
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        switch (addr - M.base) {
            case kOffIntReg: AckIntReg(value); return;
            case kOffCntReg:
                cntreg_ = static_cast<uint16_t>((value & M.cnt_writable) | M.cnt_fixed_read);
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
        w.Write("cntreg", cntreg_);
        w.Write("waitreg", waitreg_);
    }

    void RestoreState(StateReader& r) override {
        uint16_t v = 0;
        r.Read("int_reg", v);
        intreg_.store(v, std::memory_order_release);
        r.Read("cntreg", cntreg_);
        r.Read("waitreg", waitreg_);
    }

protected:
    /* Registers one chip of the family carries and the other does not (VR4121 UM
       Table 1-6 adds PMUWAITREG and PMUDIVREG over VR4102 UM Table 15-4). */
    virtual uint16_t ReadHalfExt(uint32_t addr) { return Peripheral::ReadHalf(addr); }
    virtual void WriteHalfExt(uint32_t addr, uint16_t value) {
        Peripheral::WriteHalf(addr, value);
    }
    virtual void ResetExt() {}

    uint16_t IntReg() const { return intreg_.load(std::memory_order_acquire); }

    /* A reset/shutdown cause is OR'd into PMUINTREG off the JIT thread while the
       guest is free to ack on it, so the ack is one atomic read-modify-write or a
       concurrently-latched cause is lost and the guest boots without one. */
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

    std::atomic<uint16_t> intreg_{M.int_power_on};
    uint16_t              cntreg_  = M.cnt_power_on;
    uint16_t              waitreg_ = M.wait_power_on;
};

}  /* namespace cerf_vr41xx_pmu_detail */
